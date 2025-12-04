use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    name: String,
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestReport {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub execution_time_ms: u64,
    pub environment: String,
    pub tests: Vec<TestResult>,
}

pub struct TestRunner {
    results: Vec<TestResult>,
}

impl TestRunner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    pub fn run_test<F>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce() -> anyhow::Result<()>,
    {
        log::info!("Starting test: {}", name);
        println!("Running test: {}", name);

        let test_start = std::time::Instant::now();
        let result = match test_fn() {
            Ok(()) => {
                let duration = test_start.elapsed();
                log::info!("Test '{}' PASSED in {:?}", name, duration);
                println!("  ✓ PASSED");
                TestResult {
                    name: name.to_string(),
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                let duration = test_start.elapsed();
                log::error!("Test '{}' FAILED in {:?}: {}", name, duration, e);
                println!("  ✗ FAILED: {}", e);
                TestResult {
                    name: name.to_string(),
                    success: false,
                    error: Some(e.to_string()),
                }
            }
        };

        self.results.push(result);
    }

    pub fn generate_report(&self, start_time: std::time::Instant) -> TestReport {
        let passed = self.results.iter().filter(|r| r.success).count();
        let failed = self.results.len() - passed;

        TestReport {
            total_tests: self.results.len(),
            passed,
            failed,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            environment: if cfg!(target_os = "windows") {
                "Windows".to_string()
            } else {
                "Linux/Wine".to_string()
            },
            tests: self.results.clone(),
        }
    }
}
