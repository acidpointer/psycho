;; PSYCHO specific configuration for rust-analyzer and flycheck
;; 1. It is strongly recommended to disable build scripts for rust-analyzer
;; 2. Cargo target must be changed depends on what subcrate developer work




((rust-mode
  . ((eglot-workspace-configuration
      . (:rust-analyzer (:cargo (:buildScripts (:enable :json-false)
                                 :target "i686-pc-windows-gnu"
                                 :check (:command "clippy"))))
      ))
  ))

