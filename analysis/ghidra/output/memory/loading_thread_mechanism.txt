###############################################################
# LOADING THREAD MECHANISM RESEARCH
# Goal: Does loading run on main thread or a separate thread?
# What thread calls gheap_alloc/free during coc/fast travel?
###############################################################


### SECTION 1: CellTransitionHandler (0x008774A0)
# Does it spawn a loading thread? Or run synchronously on caller?

======================================================================
CellTransitionHandler @ 0x008774a0
======================================================================
  Function: FUN_008774a0 @ 0x008774a0, Size: 561 bytes

void __thiscall FUN_008774a0(void *this,char param_1)

{
  undefined1 uVar1;
  bool bVar2;
  int iVar3;
  void *this_00;
  int *piVar4;
  int *piVar5;
  undefined *puVar6;
  undefined4 local_20;
  undefined4 local_18;
  
  uVar1 = FUN_004f1540((int)this);
  FUN_004f15a0(this,0);
  FUN_00877700((int)DAT_011dea3c);
  bVar2 = FUN_007d6bd0(DAT_011ddf38,'\0');
  FUN_00453a70();
  FUN_00ad8780();
  FUN_008324e0('\0');
  iVar3 = FUN_008d6f30((int)DAT_011dea3c);
  if (iVar3 != 0) {
    piVar4 = DAT_011dea3c;
    this_00 = (void *)FUN_008d6f30((int)DAT_011dea3c);
    FUN_0054ca90(this_00,piVar4);
  }
  piVar4 = (int *)FUN_00950bb0(DAT_011dea3c,'\x01');
  if (piVar4 == (int *)0x0) {
    local_18 = 0;
  }
  else {
    local_18 = (**(code **)(*piVar4 + 0xc))();
  }
  if (local_18 != 0) {
    iVar3 = FUN_009611e0(local_18);
    if (iVar3 != 0) {
      piVar5 = (int *)FUN_009611e0(local_18);
      (**(code **)(*piVar5 + 0xe8))(piVar4);
    }
  }
  piVar4 = (int *)FUN_00950bb0(DAT_011dea3c,'\0');
  if (piVar4 == (int *)0x0) {
    local_20 = 0;
  }
  else {
    local_20 = (**(code **)(*piVar4 + 0xc))();
  }
  if (local_20 != 0) {
    iVar3 = FUN_009611e0(local_20);
    if (iVar3 != 0) {
      piVar5 = (int *)FUN_009611e0(local_20);
      (**(code **)(*piVar5 + 0xe8))(piVar4);
    }
  }
  FUN_004539a0(DAT_011dea10,'\0','\0');
  FUN_007037c0(DAT_011dea10,0x7fffffff);
  FUN_0061cc40(DAT_011dea10,0x7fffffff);
  puVar6 = FUN_006c0720();
  FUN_006c09f0(puVar6);
  FUN_00868d70('\0');
  FUN_00c459d0('\0');
  (**(code **)(*DAT_011dea3c + 0x1cc))(0,0);
  FUN_0084a840(DAT_011ddf38);
  FUN_00970d50(0x11e0e80);
  FUN_004614e0(DAT_011c3f2c);
  iVar3 = FUN_00b4f5c0();
  FUN_00b631d0(iVar3);
  FUN_0040fbe0();
  FUN_00706320();
  FUN_0045ac80((int)DAT_011dea10);
  if (param_1 != '\0') {
    FUN_007053f0();
  }
  FUN_007d6bd0(DAT_011ddf38,bVar2);
  FUN_008776e0((int)DAT_011dea0c);
  FUN_004f15a0(DAT_011dea0c,uVar1);
  return;
}



--- Calls FROM CellTransitionHandler (0x008774a0) ---
  0x008774ac -> 0x004f1540 FUN_004f1540
  0x008774b9 -> 0x004f15a0 FUN_004f15a0
  0x008774c4 -> 0x00877700 FUN_00877700
  0x008774d1 -> 0x007d6bd0 FUN_007d6bd0
  0x008774db -> 0x00453a70 FUN_00453a70
  0x008774e2 -> 0x00ad8780 FUN_00ad8780
  0x008774e9 -> 0x008324e0 FUN_008324e0
  0x008774f7 -> 0x008d6f30 FUN_008d6f30
  0x0087750c -> 0x008d6f30 FUN_008d6f30
  0x00877513 -> 0x0054ca90 FUN_0054ca90
  0x00877520 -> 0x00950bb0 FUN_00950bb0
  0x00877556 -> 0x009611e0 FUN_009611e0
  0x00877562 -> 0x009611e0 FUN_009611e0
  0x00877586 -> 0x00950bb0 FUN_00950bb0
  0x008775bc -> 0x009611e0 FUN_009611e0
  0x008775c8 -> 0x009611e0 FUN_009611e0
  0x008775ee -> 0x004539a0 FUN_004539a0
  0x008775fe -> 0x007037c0 FUN_007037c0
  0x0087760e -> 0x0061cc40 FUN_0061cc40
  0x00877613 -> 0x006c0720 FUN_006c0720
  0x0087761a -> 0x006c09f0 FUN_006c09f0
  0x00877621 -> 0x00868d70 FUN_00868d70
  0x0087762b -> 0x00c459d0 FUN_00c459d0
  0x00877653 -> 0x0084a840 FUN_0084a840
  0x0087765d -> 0x00970d50 FUN_00970d50
  0x00877668 -> 0x004614e0 FUN_004614e0
  0x0087766d -> 0x00b4f5c0 FUN_00b4f5c0
  0x00877674 -> 0x00b631d0 FUN_00b631d0
  0x00877679 -> 0x0040fbe0 FUN_0040fbe0
  0x00877680 -> 0x00706320 FUN_00706320
  0x0087768e -> 0x0045ac80 FUN_0045ac80
  0x0087769b -> 0x007053f0 FUN_007053f0
  0x008776ab -> 0x007d6bd0 FUN_007d6bd0
  0x008776b6 -> 0x008776e0 FUN_008776e0
  0x008776c6 -> 0x004f15a0 FUN_004f15a0
  Total: 35 calls


### SECTION 2: Console command dispatch
# Where does 'coc' get processed? What thread runs it?

======================================================================
CellTransition_Conditional @ 0x0093bea0
======================================================================
  Function: FUN_0093bea0 @ 0x0093bea0, Size: 832 bytes

undefined4 __fastcall FUN_0093bea0(void *param_1)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  void *this;
  uint uVar4;
  int *piVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 uVar8;
  int *local_2c;
  char local_5;
  
  local_5 = '\0';
  if (*(int *)((int)param_1 + 0x1ec) != 0) {
    FUN_00452eb0();
    FUN_0066b0d0((void *)((int)param_1 + 0xd3c),0);
    if (*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x30) == 0) {
      if ((**(int **)((int)param_1 + 0x1ec) == 0) &&
         (*(int *)(*(int *)((int)param_1 + 0x1ec) + 4) == 0)) {
        FUN_005b5e40();
      }
      else {
        if (**(int **)((int)param_1 + 0x1ec) == 0) {
          iVar7 = *(int *)((int)param_1 + 0x1ec);
          iVar1 = *(int *)((int)param_1 + 0x1ec);
          FUN_0093c200(*(float *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),
                       *(undefined4 *)(iVar1 + 0x10),*(float *)(iVar7 + 0x14),
                       *(float *)(iVar7 + 0x18),*(float *)(iVar7 + 0x1c),
                       *(void **)(*(int *)((int)param_1 + 0x1ec) + 4),
                       *(char *)(*(int *)((int)param_1 + 0x1ec) + 0x20));
        }
        else {
          iVar7 = *(int *)((int)param_1 + 0x1ec);
          iVar1 = *(int *)((int)param_1 + 0x1ec);
          FUN_0093cce0(param_1,*(float *)(iVar1 + 8),*(float *)(iVar1 + 0xc),
                       *(undefined4 *)(iVar1 + 0x10),*(float *)(iVar7 + 0x14),
                       *(float *)(iVar7 + 0x18),*(float *)(iVar7 + 0x1c),
                       (void *)**(undefined4 **)((int)param_1 + 0x1ec),
                       *(char *)(*(int *)((int)param_1 + 0x1ec) + 0x20));
        }
        this = (void *)FUN_009306d0((int)param_1);
        FUN_00573f20(this,*(undefined4 *)(*(int *)((int)param_1 + 0x1ec) + 0x10));
        if (*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x24) != 0) {
          (**(code **)(*(int *)((int)param_1 + 0x1ec) + 0x24))
                    (*(undefined4 *)(*(int *)((int)param_1 + 0x1ec) + 0x28));
        }
        local_5 = '\x01';
      }
      if ((*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x2c) != 0) &&
         (uVar4 = FUN_00568680(*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x2c)), (uVar4 & 0xff) != 0
         )) {
        piVar5 = (int *)FUN_008d8520((int)param_1);
        puVar6 = (undefined4 *)(**(code **)(*piVar5 + 0x4d4))();
        iVar7 = FUN_007af430(*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x2c));
        bVar3 = FUN_00509420(iVar7);
        uVar4 = FUN_005682c0(*(void **)(*(int *)((int)param_1 + 0x1ec) + 0x2c),'\x01');
        if ((uVar4 != 0xffffffff) &&
           (cVar2 = FUN_00568500(*(void **)(*(int *)((int)param_1 + 0x1ec) + 0x2c),uVar4,puVar6),
           cVar2 != '\0')) {
          FUN_0088d2f0(param_1,*(void **)(*(int *)((int)param_1 + 0x1ec) + 0x2c),(int)puVar6,uVar4,
                       bVar3);
        }
      }
    }
    else {
      local_2c = (int *)FUN_00569b80(*(int *)(*(int *)((int)param_1 + 0x1ec) + 0x30));
      if (local_2c == (int *)0x0) {
        local_2c = *(int **)(*(int *)((int)param_1 + 0x1ec) + 0x30);
      }
      FUN_0093cdf0(DAT_011dea3c,local_2c);
      local_5 = '\x01';
    }
    FUN_00868d70('\x01');
    FUN_00401030(*(undefined4 **)((int)param_1 + 0x1ec));
    *(undefined4 *)((int)param_1 + 0x1ec) = 0;
  }
  uVar8 = 0;
  if (((local_5 != '\0') && (bVar3 = FUN_0042ce10(DAT_011ddf38), uVar8 = extraout_var, !bVar3)) &&
     (bVar3 = FUN_0093c1e0((int)DAT_011dea3c), uVar8 = extraout_var_00, !bVar3)) {
    FUN_005d14d0(DAT_011dea3c,'\x01');
    uVar8 = extraout_var_01;
  }
  return CONCAT31(uVar8,local_5);
}



--- Calls FROM CellTransition_Conditional (0x0093bea0) ---
  0x0093bec3 -> 0x00452eb0 FUN_00452eb0
  0x0093bed3 -> 0x0066b0d0 FUN_0066b0d0
  0x0093bef3 -> 0x00569b80 FUN_00569b80
  0x0093bf22 -> 0x0093cdf0 FUN_0093cdf0
  0x0093bfbe -> 0x0093cce0 FUN_0093cce0
  0x0093c025 -> 0x0093c200 FUN_0093c200
  0x0093c034 -> 0x009306d0 FUN_009306d0
  0x0093c04f -> 0x00573f20 FUN_00573f20
  0x0093c08c -> 0x005b5e40 FUN_005b5e40
  0x0093c0b3 -> 0x00568680 FUN_00568680
  0x0093c0c6 -> 0x008d8520 FUN_008d8520
  0x0093c0f4 -> 0x007af430 FUN_007af430
  0x0093c103 -> 0x00509420 FUN_00509420
  0x0093c121 -> 0x005682c0 FUN_005682c0
  0x0093c143 -> 0x00568500 FUN_00568500
  0x0093c16c -> 0x0088d2f0 FUN_0088d2f0
  0x0093c173 -> 0x00868d70 FUN_00868d70
  0x0093c18b -> 0x00401030 FUN_00401030
  0x0093c1ae -> 0x0042ce10 FUN_0042ce10
  0x0093c1c0 -> 0x0093c1e0 FUN_0093c1e0
  0x0093c1d4 -> 0x005d14d0 FUN_005d14d0
  Total: 21 calls


### SECTION 3: Fast travel loading path

======================================================================
FastTravel_Handler @ 0x0093cdf0
======================================================================
  Function: FUN_0093cdf0 @ 0x0093cdf0, Size: 1779 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __thiscall FUN_0093cdf0(void *this,int *param_1)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  char *pcVar4;
  void *pvVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  int *piVar8;
  float *pfVar9;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  int *unaff_FS_OFFSET;
  float10 fVar10;
  ulonglong uVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  undefined1 *puVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 local_4ac [10];
  undefined4 local_484 [10];
  undefined4 local_45c;
  CArray<class_CMFCRibbonInfo::XQAT::XQATItem,class_CMFCRibbonInfo::XQAT::XQATItem> local_458 [8];
  char local_450 [1024];
  uint local_50;
  undefined4 local_4c;
  undefined1 local_48 [5];
  char local_43;
  uint local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  int local_24;
  float local_20;
  undefined1 local_1c [12];
  int local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00f17d5f;
  local_10 = *unaff_FS_OFFSET;
  uVar2 = DAT_011c16bc ^ (uint)&stack0xfffffffc;
  *unaff_FS_OFFSET = (int)&local_10;
  local_28 = 0.0;
  local_50 = uVar2;
  FUN_005e58f0(0x33,this);
  cVar1 = (**(code **)(*(int *)this + 0x358))(uVar2);
  if ((cVar1 == '\0') || (local_28 != (float)_DAT_01012060)) {
    if ((DAT_011e0ba4 & 1) == 0) {
      DAT_011e0ba4 = DAT_011e0ba4 | 1;
      local_8 = 0;
      _DAT_011e0ba0 = FUN_00825c00(0x11f6394);
      local_8 = 0xffffffff;
    }
    iVar3 = FUN_00825c00(0x11f6394);
    local_3c = iVar3 - _DAT_011e0ba0;
    pcVar4 = FUN_00408d60(0x11d8980);
    if ((*pcVar4 != '\0') && ((local_3c == 0 || (20000 < local_3c)))) {
      FUN_00850a40(DAT_011de134);
      _DAT_011e0ba0 = FUN_00825c00(0x11f6394);
    }
    *(undefined1 *)(DAT_011dea3c + 0x83) = 1;
    FUN_00878160((int)local_48,'\x01',1,'\x01');
    FUN_004539a0(DAT_011dea10,'\x01','\0');
    FUN_00878250(local_43);
    FUN_00878200((int)local_48);
    FUN_009ea3b0(*(void **)((int)this + 400),0x800);
    uVar16 = 0;
    pvVar5 = (void *)FUN_009306d0((int)this);
    FUN_0088b0a0(pvVar5,uVar16);
    FUN_0088d640(this);
    local_38 = 0.0;
    FUN_006815c0(&local_34);
    puVar6 = (undefined4 *)(**(code **)(*DAT_011dea3c + 500))();
    local_34 = *puVar6;
    iVar3 = (**(code **)(*DAT_011dea3c + 500))();
    local_30 = *(undefined4 *)(iVar3 + 4);
    iVar3 = (**(code **)(*DAT_011dea3c + 500))();
    local_2c = *(undefined4 *)(iVar3 + 8);
    FUN_008d0500();
    FUN_00502670(local_1c,(int)DAT_011dea3c);
    uVar17 = 0;
    puVar15 = local_1c;
    uVar16 = 0;
    puVar6 = FUN_006dcd70(local_484,param_1);
    local_8 = 1;
    puVar7 = FUN_006dcd70(local_4ac,DAT_011dea3c);
    local_8._0_1_ = 2;
    fVar10 = FUN_006d4eb0(puVar7,puVar6,uVar16,puVar15,uVar17);
    local_38 = (float)fVar10;
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_004ff7e0(local_4ac);
    local_8 = 0xffffffff;
    FUN_004ff7e0(local_484);
    if (local_38 == (float)_DAT_010231b0) {
      local_4c = 0x400;
      FUN_00406d00(local_450,0x400,"FastTravel: Could not compute path length to Cell ");
      iVar3 = FUN_008d6f30((int)param_1);
      if (iVar3 != 0) {
        FUN_004037b0((undefined4 *)local_458);
        local_8 = 3;
        piVar8 = (int *)FUN_008d6f30((int)param_1);
        (**(code **)(*piVar8 + 0x90))(local_458);
        pcVar4 = (char *)FUN_00559450((undefined4 *)local_458);
        FUN_00406d50(local_450,0x400,pcVar4);
        local_8 = 0xffffffff;
        CArray<class_CMFCRibbonInfo::XQAT::XQATItem,class_CMFCRibbonInfo::XQAT::XQATItem>::RemoveAll
                  (local_458);
      }
      local_38 = 0.0;
      FUN_005b5e40();
    }
    local_24 = FUN_004839c0(0x3a);
    fVar10 = (float10)FUN_00884eb0(DAT_011dea3c);
    local_20 = (float)((float10)local_38 / fVar10) / (float)_DAT_01012640;
    fVar10 = FUN_00526ac0(local_24);
    local_20 = (float)(fVar10 * (float10)local_20);
    uVar11 = FUN_00ec62c0(extraout_ECX,extraout_EDX);
    *(int *)((int)this + 0x654) = (int)uVar11;
    *(undefined1 *)((int)this + 0x658) = 0;
    FUN_00457d70(DAT_011dea10,'\x01',(int)param_1,'\0');
    if (*(int *)((int)this + 0x654) == 0) {
      fVar12 = local_20 * (float)_DAT_01012640;
      fVar10 = (float10)FUN_00867950(0x11de7b8);
      local_20 = (float)((float10)fVar12 / fVar10);
      fVar10 = FUN_0096d490();
      FUN_0096d4b0((float)(fVar10 + (float10)local_20));
      FUN_00867a40(&DAT_011de7b8,local_20);
    }
    else {
      local_45c = *(undefined4 *)((int)this + 0x654);
      while (0 < *(int *)((int)this + 0x654)) {
        fVar10 = (float10)FUN_00867950(0x11de7b8);
        local_20 = (float)((float10)_DAT_01012640 / fVar10);
        fVar10 = FUN_0096d490();
        FUN_0096d4b0((float)(fVar10 + (float10)local_20));
        FUN_00867a40(&DAT_011de7b8,local_20);
        FUN_0040fbf0((LONG *)&DAT_011f11a0);
        FUN_0096bcd0(&DAT_011e0e80,_DAT_01084838);
        FUN_0096db30(_DAT_01084838,1,0);
        FUN_0096b810(&DAT_011e0e80,_DAT_01084838);
        FUN_0096b470(&DAT_011e0e80,_DAT_01084838);
        FUN_0096b050(&DAT_011e0e80,_DAT_01084838,'\x01');
        FUN_0096eb40(0x11e0e80);
        FUN_0040fba0((undefined4 *)&DAT_011f11a0);
        *(int *)((int)this + 0x654) = *(int *)((int)this + 0x654) + -1;
        FUN_0088b510(DAT_011dea3c,_DAT_010162c0);
      }
    }
    FUN_00973ee0(&DAT_011e0e80,param_1);
    cVar1 = FUN_0093d4f0();
    if (cVar1 != '\0') {
      FUN_0045aee0(DAT_011dea10,0);
    }
    iVar3 = FUN_00652110();
    if (iVar3 != 0) {
      cVar1 = '\0';
      pvVar5 = (void *)FUN_00652110();
      FUN_00650a30(pvVar5,cVar1);
    }
    FUN_00aa7030();
    cVar1 = '\x01';
    puVar6 = FUN_0046dd00();
    FUN_0063e8f0(puVar6,cVar1);
    DAT_011d8906 = 1;
    cVar1 = '\x01';
    pvVar5 = (void *)FUN_00575d70((int)param_1);
    pfVar9 = (float *)FUN_00430830((int)param_1);
    fVar12 = *pfVar9;
    fVar13 = pfVar9[1];
    fVar14 = pfVar9[2];
    pfVar9 = (float *)(**(code **)(*param_1 + 500))();
    FUN_0093cce0(DAT_011dea3c,*pfVar9,pfVar9[1],pfVar9[2],fVar12,fVar13,fVar14,pvVar5,cVar1);
    DAT_011d8906 = 0;
    *(undefined4 *)((int)this + 0x654) = 0;
    cVar1 = '\0';
    puVar6 = FUN_0046dd00();
    FUN_0063e8f0(puVar6,cVar1);
    cVar1 = FUN_0093d4f0();
    if (cVar1 != '\0') {
      FUN_0045aee0(DAT_011dea10,1);
    }
    FUN_00483710();
    FUN_00459870((int)DAT_011dea10);
    FUN_00972d30(0x11e0e80);
    FUN_0096df40(0x11e0e80);
    *(undefined1 *)(DAT_011dea3c + 0x83) = 0;
    FUN_00975d10(0x11e0e80);
    (**(code **)(*(int *)this + 0x3f4))();
    FUN_00961f90((int)this);
    *(undefined1 *)(DAT_011dea3c + 0x81) = 0;
  }
  *unaff_FS_OFFSET = local_10;
  __security_check_cookie(local_50 ^ (uint)&stack0xfffffffc);
  return;
}



--- Calls FROM FastTravel_Handler (0x0093cdf0) ---
  0x0093ce33 -> 0x005e58f0 FUN_005e58f0
  0x0093ce93 -> 0x00825c00 FUN_00825c00
  0x0093cea9 -> 0x00825c00 FUN_00825c00
  0x0093cebc -> 0x00408d60 FUN_00408d60
  0x0093cedd -> 0x00850a40 FUN_00850a40
  0x0093cee7 -> 0x00825c00 FUN_00825c00
  0x0093cf08 -> 0x00878160 FUN_00878160
  0x0093cf1a -> 0x004539a0 FUN_004539a0
  0x0093cf24 -> 0x00878250 FUN_00878250
  0x0093cf30 -> 0x00878200 FUN_00878200
  0x0093cf49 -> 0x009ea3b0 FUN_009ea3b0
  0x0093cf56 -> 0x009306d0 FUN_009306d0
  0x0093cf5d -> 0x0088b0a0 FUN_0088b0a0
  0x0093cf68 -> 0x0088d640 FUN_0088d640
  0x0093cf75 -> 0x006815c0 FUN_006815c0
  0x0093cff0 -> 0x008d0500 FUN_008d0500
  0x0093cfff -> 0x00502670 FUN_00502670
  0x0093d01a -> 0x006dcd70 FUN_006dcd70
  0x0093d04c -> 0x006dcd70 FUN_006dcd70
  0x0093d06e -> 0x006d4eb0 FUN_006d4eb0
  0x0093d083 -> 0x004ff7e0 FUN_004ff7e0
  0x0093d095 -> 0x004ff7e0 FUN_004ff7e0
  0x0093d0c6 -> 0x00406d00 FUN_00406d00
  0x0093d0d1 -> 0x008d6f30 FUN_008d6f30
  0x0093d0e0 -> 0x004037b0 FUN_004037b0
  0x0093d0ef -> 0x008d6f30 FUN_008d6f30
  0x0093d11d -> 0x00559450 FUN_00559450
  0x0093d12f -> 0x00406d50 FUN_00406d50
  0x0093d144 -> 0x004037d0 RemoveAll
  0x0093d155 -> 0x005b5e40 FUN_005b5e40
  0x0093d15f -> 0x004839c0 FUN_004839c0
  0x0093d170 -> 0x00884eb0 FUN_00884eb0
  0x0093d18a -> 0x00526ac0 FUN_00526ac0
  0x0093d198 -> 0x00ec62c0 FUN_00ec62c0
  0x0093d1c4 -> 0x00457d70 FUN_00457d70
  0x0093d206 -> 0x00867950 FUN_00867950
  0x0093d219 -> 0x0096d490 FUN_0096d490
  0x0093d236 -> 0x0096d4b0 FUN_0096d4b0
  0x0093d247 -> 0x00867a40 FUN_00867a40
  0x0093d253 -> 0x0040fbf0 FUN_0040fbf0
  0x0093d269 -> 0x0096bcd0 FUN_0096bcd0
  0x0093d281 -> 0x0096db30 FUN_0096db30
  0x0093d297 -> 0x0096b810 FUN_0096b810
  0x0093d2ad -> 0x0096b470 FUN_0096b470
  0x0093d2c3 -> 0x0096b050 FUN_0096b050
  0x0093d2cd -> 0x0096eb40 FUN_0096eb40
  0x0093d2d7 -> 0x0040fba0 FUN_0040fba0
  0x0093d307 -> 0x0088b510 FUN_0088b510
  0x0093d327 -> 0x00867950 FUN_00867950
  0x0093d33a -> 0x0096d490 FUN_0096d490
  0x0093d357 -> 0x0096d4b0 FUN_0096d4b0
  0x0093d368 -> 0x00867a40 FUN_00867a40
  0x0093d376 -> 0x00973ee0 FUN_00973ee0
  0x0093d37b -> 0x0093d4f0 FUN_0093d4f0
  0x0093d38f -> 0x0045aee0 FUN_0045aee0
  0x0093d394 -> 0x00652110 FUN_00652110
  0x0093d39f -> 0x00652110 FUN_00652110
  0x0093d3a6 -> 0x00650a30 FUN_00650a30
  0x0093d3ab -> 0x00aa7030 FUN_00aa7030
  0x0093d3b2 -> 0x0046dd00 FUN_0046dd00
  0x0093d3b9 -> 0x0063e8f0 FUN_0063e8f0
  0x0093d3ca -> 0x00575d70 FUN_00575d70
  0x0093d3d3 -> 0x00430830 FUN_00430830
  0x0093d418 -> 0x0093cce0 FUN_0093cce0
  0x0093d436 -> 0x0046dd00 FUN_0046dd00
  0x0093d43d -> 0x0063e8f0 FUN_0063e8f0
  0x0093d442 -> 0x0093d4f0 FUN_0093d4f0
  0x0093d456 -> 0x0045aee0 FUN_0045aee0
  0x0093d460 -> 0x00483710 FUN_00483710
  0x0093d46b -> 0x00459870 FUN_00459870
  0x0093d475 -> 0x00972d30 FUN_00972d30
  0x0093d47f -> 0x0096df40 FUN_0096df40
  0x0093d495 -> 0x00975d10 FUN_00975d10
  0x0093d4b6 -> 0x00961f90 FUN_00961f90
  0x0093d4d8 -> 0x00ec408c __security_check_cookie
  Total: 75 calls


### SECTION 4: Save load path

======================================================================
SaveLoad_Handler @ 0x0084c5a0
======================================================================
  Function: FUN_0084c5a0 @ 0x0084c5a0, Size: 1572 bytes

void __cdecl FUN_0084c5a0(void *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined1 uVar7;
  bool bVar8;
  char cVar9;
  uint uVar10;
  int *piVar11;
  undefined3 extraout_var;
  void *pvVar12;
  float *pfVar13;
  undefined3 extraout_var_00;
  char *pcVar14;
  long lVar15;
  void *pvVar16;
  undefined **ppuVar17;
  undefined **ppuVar18;
  char **_EndPtr;
  int iVar19;
  char *_SubStr;
  int *local_7c;
  int local_54;
  float local_48;
  float local_44;
  undefined4 local_40;
  int local_3c;
  int *local_38;
  int local_34;
  void *local_30;
  void *local_2c;
  void *local_28;
  int local_24;
  int local_20;
  undefined1 local_1c [4];
  int local_18;
  char local_11;
  float local_10;
  float local_c;
  undefined4 local_8;
  
  FUN_00864980(param_1,local_1c,4);
  iVar19 = 0;
  ppuVar18 = &PTR_PTR_01183fd0;
  ppuVar17 = &PTR_PTR_01183028;
  uVar10 = FUN_008648a0(param_1);
  piVar11 = (int *)FUN_004839c0(uVar10);
  local_24 = FUN_00ec43fb(piVar11,0,(_s_RTTICompleteObjectLocator *)ppuVar17,
                          (TypeDescriptor *)ppuVar18,iVar19);
  FUN_00864980(param_1,&local_18,4);
  FUN_00864980(param_1,&local_20,4);
  uVar10 = FUN_008648a0(param_1);
  local_28 = (void *)FUN_004839c0(uVar10);
  FUN_006815c0(&local_10);
  FUN_00864980(param_1,&local_10,0xc);
  FUN_0078d770(param_1);
  local_11 = '\x01';
  if (local_28 == (void *)0x0) {
    local_11 = '\0';
  }
  else {
    uVar7 = FUN_00401170((int)local_28);
    if (CONCAT31(extraout_var,uVar7) == 0x39) {
      local_2c = local_28;
      pvVar12 = (void *)FUN_008d6f30((int)DAT_011dea3c);
      if (pvVar12 != local_2c) {
        cVar9 = '\0';
        pvVar12 = local_2c;
        pfVar13 = (float *)FUN_00430830((int)DAT_011dea3c);
        FUN_0093c200(local_10,local_c,local_8,*pfVar13,pfVar13[1],pfVar13[2],pvVar12,cVar9);
      }
      if (local_24 != 0) {
        FUN_00458200(DAT_011dea10,local_24);
      }
      FUN_007037c0(DAT_011dea10,local_18);
      FUN_0061cc40(DAT_011dea10,local_20);
    }
    else {
      uVar7 = FUN_00401170((int)local_28);
      if (CONCAT31(extraout_var_00,uVar7) == 0x41) {
        if (local_24 != 0) {
          FUN_00458200(DAT_011dea10,local_24);
        }
        local_30 = local_28;
        bVar8 = FUN_00586260((int)local_28);
        if (((bVar8) && (pcVar14 = FUN_00408d60(0x11e08e0), *pcVar14 != '\0')) &&
           (cVar9 = FUN_00588d10(local_30,&local_10), cVar9 == '\0')) {
          local_11 = '\0';
        }
        if (local_11 != '\0') {
          FUN_006815c0(&local_48);
          local_48 = (float)(local_18 << 0xc);
          local_44 = (float)(local_20 << 0xc);
          local_40 = 0;
          FUN_00452580(DAT_011dea10,&local_48,'\0');
          FUN_00457d70(DAT_011dea10,'\x01',(int)local_28,'\0');
          local_3c = FUN_00406d90(local_10);
          local_3c = local_3c >> 0xc;
          local_34 = FUN_00406d90(local_c);
          local_34 = local_34 >> 0xc;
          local_38 = FUN_00461c20(DAT_011c3f2c,local_3c,local_34,local_30,'\0');
          if ((local_38 == (int *)0x0) || (iVar19 = FUN_00545cb0((int)local_38), iVar19 == 0)) {
            iVar19 = FUN_008d6f30((int)DAT_011dea3c);
            if (iVar19 != 0) {
              piVar11 = DAT_011dea3c;
              pvVar12 = (void *)FUN_008d6f30((int)DAT_011dea3c);
              FUN_0054ca90(pvVar12,piVar11);
            }
            FUN_00454450(DAT_011dea10,&local_48);
            local_38 = FUN_00461c20(DAT_011c3f2c,local_3c,local_34,local_30,'\x01');
          }
          if (local_38 == (int *)0x0) {
            local_11 = '\0';
          }
          else {
            FUN_0084cbf0(DAT_011ddf38,'\x01');
            cVar9 = '\0';
            piVar11 = local_38;
            pfVar13 = (float *)FUN_00430830((int)DAT_011dea3c);
            FUN_0093c200(local_10,local_c,local_8,*pfVar13,pfVar13[1],pfVar13[2],piVar11,cVar9);
            FUN_0084cbf0(DAT_011ddf38,'\0');
          }
        }
      }
      else {
        local_11 = '\0';
      }
    }
  }
  if (local_11 != '\0') {
LAB_0084cb9d:
    FUN_004539a0(DAT_011dea10,'\x01','\0');
    FUN_00868d70('\0');
    FUN_00c459d0('\0');
    return;
  }
  FUN_0084cc40(DAT_011ddf38,'\x01');
  local_54 = FUN_00455600((int)DAT_011c3f2c);
LAB_0084c8f1:
  if ((local_54 == 0) || (piVar11 = (int *)FUN_006815c0(local_54), *piVar11 == 0))
  goto LAB_0084c99f;
  piVar11 = (int *)FUN_006815c0(local_54);
  FUN_0084e3a0(*piVar11);
  piVar11 = (int *)FUN_006815c0(local_54);
  FUN_00408da0(*piVar11 + 0x30);
  FUN_0084cbd0((wchar_t *)"Quest %s (%08x) compared to Patch04Debug\n");
  piVar11 = (int *)FUN_006815c0(local_54);
  uVar10 = FUN_0048cee0(*piVar11 + 0x30);
  if (8 < uVar10) {
    _SubStr = "Patch04Debug";
    piVar11 = (int *)FUN_006815c0(local_54);
    pcVar14 = FUN_00408da0(*piVar11 + 0x30);
    pcVar14 = _strstr(pcVar14,_SubStr);
    if (pcVar14 != (char *)0x0) {
      piVar11 = (int *)FUN_006815c0(local_54);
      DAT_011dea3c[0x393] = *piVar11;
LAB_0084c99f:
      FUN_0095f530(DAT_011dea3c,'\0',0xff);
      iVar19 = 0x10;
      _EndPtr = (char **)0x0;
      pcVar14 = (char *)FUN_00403df0(0x11de25c);
      lVar15 = _strtol(pcVar14,_EndPtr,iVar19);
      iVar19 = 0;
      ppuVar18 = &PTR_PTR_011841cc;
      ppuVar17 = &PTR_PTR_01183028;
      piVar11 = (int *)FUN_004839c0(lVar15);
      piVar11 = (int *)FUN_00ec43fb(piVar11,0,(_s_RTTICompleteObjectLocator *)ppuVar17,
                                    (TypeDescriptor *)ppuVar18,iVar19);
      if (piVar11 != (int *)0x0) {
        pfVar13 = (float *)(**(code **)(*piVar11 + 500))();
        fVar1 = *pfVar13;
        fVar2 = pfVar13[1];
        fVar3 = pfVar13[2];
        pfVar13 = (float *)FUN_00430830((int)piVar11);
        fVar4 = *pfVar13;
        fVar5 = pfVar13[1];
        fVar6 = pfVar13[2];
        pvVar12 = (void *)FUN_008d6f30((int)piVar11);
        pvVar16 = (void *)FUN_00575d70((int)piVar11);
        local_11 = '\x01';
        if (pvVar16 == (void *)0x0) {
          if (pvVar12 == (void *)0x0) {
            local_11 = '\0';
          }
          else {
            FUN_0093c200(fVar1,fVar2,fVar3,fVar4,fVar5,fVar6,pvVar12,'\x01');
          }
        }
        else {
          FUN_0093cce0(DAT_011dea3c,fVar1,fVar2,fVar3,fVar4,fVar5,fVar6,pvVar16,'\x01');
        }
      }
      if (local_11 == '\0') {
        iVar19 = 0;
        ppuVar18 = &PTR_PTR_01183fd0;
        ppuVar17 = &PTR_PTR_01183028;
        piVar11 = (int *)FUN_004839c0(0xda726);
        pvVar12 = (void *)FUN_00ec43fb(piVar11,0,(_s_RTTICompleteObjectLocator *)ppuVar17,
                                       (TypeDescriptor *)ppuVar18,iVar19);
        if (pvVar12 != (void *)0x0) {
          local_7c = (int *)FUN_005875a0(pvVar12,-0x12,0);
          if (local_7c == (int *)0x0) {
            local_7c = FUN_00585b30(pvVar12,0xffffffee,0);
          }
          if (local_7c == (int *)0x0) {
            local_7c = (int *)FUN_005875a0(pvVar12,0,0);
          }
          if (local_7c == (int *)0x0) {
            local_7c = FUN_00585b30(pvVar12,0,0);
          }
          if (local_7c == (int *)0x0) {
            local_7c = FUN_00461330(0,0,0,pvVar12);
          }
          if (local_7c != (int *)0x0) {
            FUN_0093db60(DAT_011dea3c,(char *)0x0,local_7c);
          }
        }
      }
      goto LAB_0084cb9d;
    }
  }
  local_54 = FUN_00726070(local_54);
  goto LAB_0084c8f1;
}



--- Calls FROM SaveLoad_Handler (0x0084c5a0) ---
  0x0084c5b2 -> 0x00864980 FUN_00864980
  0x0084c5c6 -> 0x008648a0 FUN_008648a0
  0x0084c5cc -> 0x004839c0 FUN_004839c0
  0x0084c5d7 -> 0x00ec43fb FUN_00ec43fb
  0x0084c5eb -> 0x00864980 FUN_00864980
  0x0084c5f9 -> 0x00864980 FUN_00864980
  0x0084c601 -> 0x008648a0 FUN_008648a0
  0x0084c607 -> 0x004839c0 FUN_004839c0
  0x0084c615 -> 0x006815c0 FUN_006815c0
  0x0084c623 -> 0x00864980 FUN_00864980
  0x0084c62c -> 0x0078d770 FUN_0078d770
  0x0084c645 -> 0x00401170 FUN_00401170
  0x0084c65f -> 0x008d6f30 FUN_008d6f30
  0x0084c675 -> 0x00430830 FUN_00430830
  0x0084c6ab -> 0x0093c200 FUN_0093c200
  0x0084c6c0 -> 0x00458200 FUN_00458200
  0x0084c6cf -> 0x007037c0 FUN_007037c0
  0x0084c6de -> 0x0061cc40 FUN_0061cc40
  0x0084c6eb -> 0x00401170 FUN_00401170
  0x0084c709 -> 0x00458200 FUN_00458200
  0x0084c717 -> 0x00586260 FUN_00586260
  0x0084c728 -> 0x00408d60 FUN_00408d60
  0x0084c73b -> 0x00588d10 FUN_00588d10
  0x0084c75a -> 0x006815c0 FUN_006815c0
  0x0084c78e -> 0x00452580 FUN_00452580
  0x0084c7a1 -> 0x00457d70 FUN_00457d70
  0x0084c7ad -> 0x00406d90 FUN_00406d90
  0x0084c7c2 -> 0x00406d90 FUN_00406d90
  0x0084c7e4 -> 0x00461c20 FUN_00461c20
  0x0084c7f5 -> 0x00545cb0 FUN_00545cb0
  0x0084c804 -> 0x008d6f30 FUN_008d6f30
  0x0084c81a -> 0x008d6f30 FUN_008d6f30
  0x0084c821 -> 0x0054ca90 FUN_0054ca90
  0x0084c830 -> 0x00454450 FUN_00454450
  0x0084c849 -> 0x00461c20 FUN_00461c20
  0x0084c85f -> 0x0084cbf0 FUN_0084cbf0
  0x0084c870 -> 0x00430830 FUN_00430830
  0x0084c8a6 -> 0x0093c200 FUN_0093c200
  0x0084c8b3 -> 0x0084cbf0 FUN_0084cbf0
  0x0084c8de -> 0x0084cc40 FUN_0084cc40
  0x0084c8e9 -> 0x00455600 FUN_00455600
  0x0084c8fe -> 0x006815c0 FUN_006815c0
  0x0084c90f -> 0x006815c0 FUN_006815c0
  0x0084c916 -> 0x0084e3a0 FUN_0084e3a0
  0x0084c91f -> 0x006815c0 FUN_006815c0
  0x0084c929 -> 0x00408da0 FUN_00408da0
  0x0084c934 -> 0x0084cbd0 FUN_0084cbd0
  0x0084c93f -> 0x006815c0 FUN_006815c0
  0x0084c949 -> 0x0048cee0 FUN_0048cee0
  0x0084c95b -> 0x006815c0 FUN_006815c0
  0x0084c965 -> 0x00408da0 FUN_00408da0
  0x0084c96b -> 0x00ec7750 _strstr
  0x0084c97a -> 0x006815c0 FUN_006815c0
  0x0084c992 -> 0x00726070 FUN_00726070
  0x0084c9ac -> 0x0095f530 FUN_0095f530
  0x0084c9ba -> 0x00403df0 FUN_00403df0
  0x0084c9c0 -> 0x00ec8d08 _strtol
  0x0084c9db -> 0x004839c0 FUN_004839c0
  0x0084c9e6 -> 0x00ec43fb FUN_00ec43fb
  0x0084ca1f -> 0x00430830 FUN_00430830
  0x0084ca38 -> 0x008d6f30 FUN_008d6f30
  0x0084ca43 -> 0x00575d70 FUN_00575d70
  0x0084ca8d -> 0x0093cce0 FUN_0093cce0
  0x0084cad2 -> 0x0093c200 FUN_0093c200
  0x0084cafa -> 0x004839c0 FUN_004839c0
  0x0084cb05 -> 0x00ec43fb FUN_00ec43fb
  0x0084cb21 -> 0x005875a0 FUN_005875a0
  0x0084cb36 -> 0x00585b30 FUN_00585b30
  0x0084cb4b -> 0x005875a0 FUN_005875a0
  0x0084cb60 -> 0x00585b30 FUN_00585b30
  0x0084cb7e -> 0x00461330 FUN_00461330
  0x0084cb98 -> 0x0093db60 FUN_0093db60
  0x0084cba7 -> 0x004539a0 FUN_004539a0
  0x0084cbae -> 0x00868d70 FUN_00868d70
  0x0084cbb8 -> 0x00c459d0 FUN_00c459d0
  Total: 75 calls


### SECTION 5: Who sets LOADING_FLAG (0x011DEA2B)?
# This tells us what thread initiates loading

----------------------------------------------------------------------
References TO 0x011dea2b (LOADING_FLAG)
----------------------------------------------------------------------
  WRITE @ 0x0086e6e1 (in FUN_0086e650)
  READ @ 0x0086e771 (in FUN_0086e650)
  WRITE @ 0x0086e7c9 (in FUN_0086e650)
  READ @ 0x0086e871 (in FUN_0086e650)
  READ @ 0x0086e8e0 (in FUN_0086e650)
  READ @ 0x0086e90f (in FUN_0086e650)
  READ @ 0x0086e93d (in FUN_0086e650)
  READ @ 0x0086ea0e (in FUN_0086e650)
  READ @ 0x0086ea5a (in FUN_0086e650)
  READ @ 0x0086eae9 (in FUN_0086e650)
  READ @ 0x0086ec1d (in FUN_0086e650)
  READ @ 0x0086ed1f (in FUN_0086e650)
  READ @ 0x0086ee0c (in FUN_0086e650)
  READ @ 0x0086f199 (in FUN_0086f190)
  READ @ 0x0086f281 (in FUN_0086f260)
  READ @ 0x0086f2e5 (in FUN_0086f260)
  READ @ 0x0086f457 (in FUN_0086f450)
  READ @ 0x0086f4fc (in FUN_0086f450)
  READ @ 0x0086f7ed (in FUN_0086f6a0)
  READ @ 0x0086f95f (in FUN_0086f940)
  READ @ 0x0086fbe8 (in FUN_0086fbe0)
  READ @ 0x0086fc69 (in FUN_0086fc60)
  READ @ 0x0086fced (in FUN_0086fc60)
  READ @ 0x0086f8b0 (in FUN_0086f890)
  READ @ 0x0086f90c (in FUN_0086f890)
  READ @ 0x009443c7 (in FUN_009443c0)
  Total: 26 refs


### SECTION 6: Thread creation in loading-related functions
# Does CellTransitionHandler or its callees create threads?

----------------------------------------------------------------------
References TO 0x00ecd0cc (CreateThread (IAT))
----------------------------------------------------------------------
  Total: 0 refs

----------------------------------------------------------------------
References TO 0x00ecd084 (_beginthreadex (IAT))
----------------------------------------------------------------------
  Total: 0 refs


### SECTION 7: BSTaskManagerThread task queue during loading
# Who queues tasks for BST? What thread does BST run on?

======================================================================
IOManager_DequeueCompleted @ 0x00c3e420
======================================================================
  Function: FUN_00c3e420 @ 0x00c3e420, Size: 97 bytes

uint __thiscall FUN_00c3e420(void *this,int *param_1)

{
  uint in_EAX;
  undefined4 uVar1;
  uint local_8;
  
  local_8 = 0;
  while( true ) {
    if (*(uint *)((int)this + 8) <= local_8) {
      return in_EAX & 0xffffff00;
    }
    uVar1 = FUN_00c3e490(*(void **)(*(int *)((int)this + 4) + local_8 * 4),param_1);
    if ((char)uVar1 != '\0') break;
    in_EAX = local_8 + 1;
    local_8 = in_EAX;
  }
  uVar1 = (**(code **)(*(int *)this + 8))();
  return CONCAT31((int3)((uint)uVar1 >> 8),1);
}



--- Calls FROM IOManager_DequeueCompleted (0x00c3e420) ---
  0x00c3e456 -> 0x00c3e490 FUN_00c3e490
  Total: 1 calls

======================================================================
BSTaskManager_MainLoop @ 0x00c3d440
======================================================================
  Function: FUN_00c3d440 @ 0x00c3d440, Size: 174 bytes

void __fastcall FUN_00c3d440(int *param_1)

{
  char cVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  
  if (param_1[0xb] == 0) {
    FUN_0043db70(param_1);
  }
  else {
    uVar2 = InterlockedIncrement((LONG *)&lpAddend_01202d9c);
    __allshr(0x10,param_1[5]);
    cVar1 = (**(code **)(*param_1 + 0x2c))();
    uVar3 = __allshl(0x38,(int)cVar1 >> 0x1f);
    uVar4 = __allshl(0x18,0);
    uVar5 = __allshl(0x10,0);
    uVar5 = uVar3 | uVar4 | uVar5;
    param_1[4] = (uint)uVar5 | uVar2 & 0xffff;
    param_1[5] = (int)(uVar5 >> 0x20);
  }
  return;
}



--- Calls FROM BSTaskManager_MainLoop (0x00c3d440) ---
  0x00c3d45d -> 0x00000066 ???
  0x00c3d472 -> 0x00ec77e0 __allshr
  0x00c3d4a3 -> 0x00ec7810 __allshl
  0x00c3d4b3 -> 0x00ec7810 __allshl
  0x00c3d4c3 -> 0x00ec7810 __allshl
  0x00c3d4e3 -> 0x0043db70 FUN_0043db70
  Total: 6 calls


### SECTION 8: 89MB terrain LOD texture allocation
# What function allocates the large terrain texture?
# D3DXCreateTextureFromFileInMemory or similar

======================================================================
TextureCreate @ 0x00a61e90
======================================================================
  Function: FUN_00a61e60 @ 0x00a61e60, Size: 88 bytes
  NOTE: Requested 0x00a61e90 is inside FUN_00a61e60 (entry at 0x00a61e60)

void __cdecl FUN_00a61e60(int *param_1)

{
  char *pcVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  puVar3 = (undefined4 *)(**(code **)(*param_1 + 0x9c))();
  pcVar1 = (char *)*puVar3;
  iVar4 = FUN_00af4170(pcVar1,'\x01');
  uVar5 = FUN_00a61530(pcVar1 + iVar4);
  uVar6 = 0;
  puVar3 = (undefined4 *)(DAT_011f4464 + uVar5 * 4);
  do {
    for (piVar2 = (int *)*puVar3; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[2]) {
      if (param_1 == (int *)*piVar2) {
        if (piVar2 != (int *)0x0) {
          return;
        }
        break;
      }
    }
    uVar6 = uVar6 + 1;
    puVar3 = puVar3 + 0x2ca;
    if (6 < uVar6) {
      return;
    }
  } while( true );
}



--- Calls FROM TextureCreate (0x00a61e90) ---
  0x00a61e77 -> 0x00af4170 FUN_00af4170
  0x00a61e7f -> 0x00a61530 FUN_00a61530
  Total: 2 calls


### SECTION 9: Game's own GetCurrentThreadId (0x0040FC90)
# How does the game check main thread?

======================================================================
Game_GetCurrentThreadId @ 0x0040fc90
======================================================================
  Function: FUN_0040fc90 @ 0x0040fc90, Size: 11 bytes

void FUN_0040fc90(void)

{
  GetCurrentThreadId();
  return;
}



----------------------------------------------------------------------
References TO 0x0040fc90 (Game_GetCurrentThreadId)
----------------------------------------------------------------------
  UNCONDITIONAL_CALL @ 0x0040fc03 (in FUN_0040fbf0)
  UNCONDITIONAL_CALL @ 0x004739df (in FUN_004739b0)
  UNCONDITIONAL_CALL @ 0x004739fa (in FUN_004739b0)
  UNCONDITIONAL_CALL @ 0x00444bdd (in FUN_00444850)
  UNCONDITIONAL_CALL @ 0x00713eac (in FUN_00713e20)
  UNCONDITIONAL_CALL @ 0x0078d217 (in FUN_0078d200)
  UNCONDITIONAL_CALL @ 0x0044e3f3 (in FUN_0044e3a0)
  UNCONDITIONAL_CALL @ 0x0086c53c (in FUN_0086c160)
  UNCONDITIONAL_CALL @ 0x006b8f51 (in FUN_006b8f40)
  UNCONDITIONAL_CALL @ 0x006cb0f6 (in FUN_006cb050)
  UNCONDITIONAL_CALL @ 0x006cb50e (in FUN_006cb4c0)
  UNCONDITIONAL_CALL @ 0x006a7d71 (in FUN_006a7d60)
  UNCONDITIONAL_CALL @ 0x006a1641 (in FUN_006a1630)
  UNCONDITIONAL_CALL @ 0x006b3391 (in FUN_006b3380)
  UNCONDITIONAL_CALL @ 0x006f3da1 (in FUN_006f3d90)
  UNCONDITIONAL_CALL @ 0x00866aa0 (in FUN_00866a90)
  UNCONDITIONAL_CALL @ 0x0087a7a3 (in FUN_0087a790)
  UNCONDITIONAL_CALL @ 0x0087a857 (in FUN_0087a850)
  UNCONDITIONAL_CALL @ 0x008c7aec (in FUN_008c7aa0)
  UNCONDITIONAL_CALL @ 0x00866c56 (in FUN_00866a90)
  UNCONDITIONAL_CALL @ 0x00866c88 (in FUN_00866a90)
  UNCONDITIONAL_CALL @ 0x00440396 (in FUN_00440310)
  UNCONDITIONAL_CALL @ 0x00446f52 (in FUN_00446f40)
  UNCONDITIONAL_CALL @ 0x00446fd2 (in FUN_00446fc0)
  UNCONDITIONAL_CALL @ 0x00996431 (in FUN_00996420)
  Total: 25 refs


### SECTION 10: Where does TES store main thread ID?

======================================================================
GetMainThreadId_from_TES @ 0x0044edb0
======================================================================
  Function: FUN_0044edb0 @ 0x0044edb0, Size: 17 bytes

undefined4 __fastcall FUN_0044edb0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x10);
}

