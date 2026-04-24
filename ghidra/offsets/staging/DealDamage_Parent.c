
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void DealDamage_Parent(long *param_1,undefined8 *param_2,long param_3,long *param_4,ulong *param_5,
                      ulong *param_6,int *param_7,long param_8)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  char cVar9;
  undefined1 uVar10;
  uint uVar11;
  long lVar12;
  long lVar13;
  ulong *puVar14;
  undefined8 uVar15;
  ulong uVar16;
  ulong *puVar17;
  long *plVar18;
  long lVar19;
  long lVar20;
  ulong uVar21;
  ulong uVar22;
  long lVar23;
  undefined4 uVar24;
  undefined8 in_stack_00000070;
  ulong *in_stack_00000078;
  undefined4 in_stack_00000080;
  undefined8 in_stack_00000088;
  undefined8 in_stack_00000090;
  ulong *local_788;
  undefined8 local_780;
  ulong local_778;
  undefined8 uStack_770;
  undefined8 local_768;
  undefined8 uStack_760;
  int local_758;
  undefined8 local_750;
  undefined8 uStack_748;
  ulong local_740;
  ulong uStack_738;
  ulong local_730;
  ulong uStack_728;
  int local_720;
  int local_71c;
  undefined8 local_5d0;
  undefined4 uStack_5c8;
  uint uStack_5c4;
  ulong local_5c0;
  ulong local_5b8;
  ulong local_5b0;
  undefined8 uStack_5a8;
  undefined8 uStack_5a0;
  undefined8 uStack_598;
  ulong local_590;
  undefined8 uStack_588;
  undefined8 uStack_580;
  ulong uStack_578;
  ulong local_570;
  ulong uStack_568;
  ulong uStack_560;
  undefined8 local_558;
  undefined8 local_550;
  undefined8 uStack_548;
  undefined8 uStack_540;
  undefined8 uStack_538;
  undefined8 local_530;
  undefined8 uStack_528;
  undefined8 uStack_520;
  undefined8 uStack_518;
  undefined8 local_510;
  undefined8 uStack_508;
  undefined8 local_400;
  undefined8 uStack_3f8;
  undefined1 local_358;
  undefined8 local_350;
  undefined8 local_348;
  ulong local_340;
  undefined8 local_338;
  long local_330;
  int local_328;
  int local_324;
  undefined8 local_320;
  undefined8 uStack_318;
  undefined8 local_310;
  undefined8 uStack_308;
  undefined1 local_300;
  undefined1 auStack_2c0 [424];
  undefined1 auStack_118 [56];
  ulong local_e0;
  ulong uStack_d8;
  ulong local_d0;
  ulong local_c8;
  undefined *local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined *local_90;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 uStack_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 uStack_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_1084028b8;
  if (param_4 != (long *)0x0) {
    uStack_5c4 = uStack_5c4 & 0xffffff00;
    lVar12 = __ZN3ecs11EntityWorld12GetComponentIKN2ls18TransformComponentELb1EEEPT_NS2_2IDINS_18EntityHandleTraitsEEENSt3__117integral_constantIbLb0EEE
                       (*param_1,*param_5);
    if (lVar12 != 0) {
      uStack_5c8 = *(undefined4 *)(lVar12 + 0x18);
      uStack_5c4 = CONCAT31(uStack_5c4._1_3_,1);
      local_5d0 = *(undefined8 *)(lVar12 + 0x10);
    }
    lVar12 = (**(code **)(*param_4 + 0x38))(param_4);
    uVar8 = _UNK_10783b168;
    uVar7 = _UNK_10783b160;
    uVar6 = _UNK_10783b018;
    uVar5 = _DAT_10783b010;
    if (lVar12 != 0) {
      lVar23 = 0;
      do {
        lVar13 = (**(code **)(*param_4 + 0x48))(param_4,lVar23);
        if (lVar13 != 0) {
          uVar21 = param_6[0xe];
          if ((char)param_6[0x11] == '\0') {
            uVar21 = 1;
          }
          if ((*(ulong *)(lVar13 + 0x38) & uVar21) != 0 && (*(ulong *)(lVar13 + 0x38) & 0x2000) == 0
             ) {
            iVar1 = *(int *)(lVar13 + 0x30);
            puVar17 = in_stack_00000078;
            if (-1 < iVar1) {
              if (*(char *)(lVar13 + 0x45) == '\r') {
LAB_10538ed88:
                uStack_3f8 = uVar8;
                local_400 = uVar7;
                local_e0 = ___ZN3eoc9interrupt10Dependency4NoneE;
                uStack_d8 = uRam0000000108a6fcc8;
                local_d0 = uRam0000000108a6fcd0;
                uVar15 = __ZTWN12_GLOBAL__N_14s_MTE();
                uVar16 = __ZNSt3__124uniform_int_distributionIyEclINS_23mersenne_twister_engineIyLm64ELm312ELm156ELm31ELy13043109905998158313ELm29ELy6148914691236517205ELm17ELy8202884508482404352ELm37ELy18444473444759240704ELm43ELy6364136223846793005EEEEEyRT_RKNS1_10param_typeE
                                   (uVar15,&local_400);
                uVar15 = __ZTWN12_GLOBAL__N_14s_MTE();
                uVar15 = __ZNSt3__124uniform_int_distributionIyEclINS_23mersenne_twister_engineIyLm64ELm312ELm156ELm31ELy13043109905998158313ELm29ELy6148914691236517205ELm17ELy8202884508482404352ELm37ELy18444473444759240704ELm43ELy6364136223846793005EEEEEyRT_RKNS1_10param_typeE
                                   (uVar15,&local_400);
                uStack_760 = *(undefined8 *)(lVar13 + 0x18);
                local_768 = *(undefined8 *)(lVar13 + 0x10);
                uVar2 = *(uint *)(param_8 + 0x40);
                local_778 = uVar16;
                uStack_770 = uVar15;
                if (uVar2 != 0xffffffff) {
                  __ZN2ls3gst7AcquireEj(uVar2);
                }
                uStack_748 = *(undefined8 *)(param_8 + 0xa8);
                local_750 = *(undefined8 *)(param_8 + 0xa0);
                uStack_738 = in_stack_00000078[1];
                local_740 = *in_stack_00000078;
                local_730 = in_stack_00000078[2];
                iVar3 = *param_7;
                uStack_728 = uVar21;
                if (iVar3 != -1) {
                  __ZN2ls3gst7AcquireEj(iVar3);
                }
                uStack_548 = 0;
                local_550 = 0;
                uStack_538 = 0;
                uStack_540 = 0;
                uStack_528 = 0;
                local_530 = 0;
                uStack_518 = 0;
                uStack_520 = 0;
                local_510 = 0;
                uStack_5a8 = uStack_770;
                local_5b0 = local_778;
                uStack_598 = uStack_760;
                uStack_5a0 = local_768;
                local_570 = uStack_738;
                uStack_578 = local_740;
                uStack_560 = uStack_728;
                uStack_568 = local_730;
                local_758 = -1;
                local_720 = -1;
                uStack_508 = 7;
                uStack_580 = uStack_748;
                uStack_588 = local_750;
                local_590 = (ulong)uVar2;
                uVar21 = *param_5;
                uVar22 = uVar21 >> 0x36;
                local_558 = CONCAT44(iVar1,iVar3);
                puVar17 = (ulong *)&__ZN2ls4Guid7s_EmptyE;
                uVar2 = (uint)(uVar21 >> 0x20);
                local_71c = iVar1;
                uVar10 = 7;
                if ((uVar2 >> 0x16 < 0x41) && (uVar21 != 0xffc0000000000000)) {
                  lVar20 = *param_1;
                  uVar4 = *(uint *)
                           PTR___ZN2ls6TypeIdINS_4uuid9ComponentEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE_1083d3290
                  ;
                  puVar17 = (ulong *)__ZNK3ecs6legacy19ImmediateWorldCache9GetChangeEN2ls2IDINS_18EntityHandleTraitsEEENS_11ComponentIdE
                                               (*(undefined8 *)(lVar20 + 0x3f0),uVar21,
                                                (ulong)uVar4 & 0x7fff);
                  if (puVar17 == (ulong *)0x0) {
                    plVar18 = *(long **)(lVar20 + 0x2d0);
                    uVar11 = (uint)uVar21;
                    if ((int)uVar11 < *(int *)((long)plVar18 + uVar22 * 0x10 + 0x5c)) {
                      lVar19 = *(long *)(plVar18[uVar22 * 2 + 10] +
                                        (long)((int)uVar11 >>
                                              (*(ushort *)(plVar18 + uVar22 * 2 + 0xb) & 0x1f)) * 8)
                      ;
                      uVar11 = uVar11 & (-1 << (ulong)(*(ushort *)(plVar18 + uVar22 * 2 + 0xb) &
                                                      0x1f) ^ 0xffffffffU);
                      if (*(uint *)(lVar19 + (-(ulong)(uVar11 >> 0x1f) & 0xfffffff800000000 |
                                             (ulong)uVar11 << 3)) == (uVar2 & 0x3fffff)) {
                        uVar22 = *(ulong *)(*(long *)(*plVar18 +
                                                     (ulong)*(ushort *)
                                                             (lVar19 + (long)(int)uVar11 * 8 + 4) *
                                                     8) + ((ulong)(uVar4 >> 6) & 0x1ff) * 8) >>
                                 ((ulong)uVar4 & 0x3f) & 1;
                        goto joined_r0x00010538ef84;
                      }
                    }
                  }
                  else {
                    uVar22 = *puVar17;
joined_r0x00010538ef84:
                    if (uVar22 != 0) {
                      puVar17 = (ulong *)__ZN3ecs11EntityWorld12GetComponentIKN2ls4uuid9ComponentELb1EEEPT_NS2_2IDINS_18EntityHandleTraitsEEENSt3__117integral_constantIbLb0EEE
                                                   (lVar20,uVar21);
                      uVar10 = (undefined1)uStack_508;
                      goto LAB_10538ef94;
                    }
                  }
                  puVar17 = (ulong *)&__ZN2ls4Guid7s_EmptyE;
                  uVar10 = 7;
                }
LAB_10538ef94:
                local_358 = uVar10;
                uVar21 = *puVar17;
                uVar22 = puVar17[1];
                func_0x0001016f3550(&local_400,&local_5b0);
                local_350 = *(undefined8 *)(param_8 + 8);
                local_348 = 0xffc0000000000000;
                local_340 = *param_5;
                local_338 = 0xffc0000000000000;
                local_788 = &local_5c0;
                local_780 = 1;
                local_5c0 = uVar21;
                local_5b8 = uVar22;
                func_0x00010537f02c(&local_330,&local_788);
                uStack_318 = *(undefined8 *)(param_8 + 0x68);
                local_320 = *(undefined8 *)(param_8 + 0x60);
                uStack_308 = CONCAT44(uStack_5c4,uStack_5c8);
                local_310 = local_5d0;
                local_300 = 0;
                __ZN2ls7VariantIJN3eoc9interrupt14SpellCastEventENS2_12CastHitEventENS2_14SpellRollEventENS2_20ConditionalRollEventENS2_21LeaveAttackRangeEventENS2_21EnterAttackRangeEventENS2_19SpellPreDamageEventENS2_25PlaceholderSpellRollEventENS2_20ConditionResultEventENS2_18StatusAppliedEventENS2_10DeathEventENS2_10DebugEventEEE7Storage7DestroyIJLi0ELi1ELi2ELi3ELi4ELi5ELi6ELi7ELi8ELi9ELi10ELi11EEEEvNSt3__116integer_sequenceIiJXspT_EEEE
                          (&local_5b0);
                func_0x000105363464(in_stack_00000090,&local_400);
                lVar20 = local_330;
                local_d0 = CONCAT71(local_d0._1_7_,1);
                local_e0 = uVar16;
                uStack_d8 = uVar15;
                if (local_328 != 0) {
                  if (0 < local_324) {
                    local_324 = 0;
                  }
                  if (DAT_108aefa98 == (undefined *)0x0) {
                    uRam0000000108aefaa8 = uVar6;
                    _DAT_108aefaa0 = uVar5;
                    DAT_108aefab0 = 4000;
                    DAT_108aefb58 = 0;
                    uRam0000000108aefac0 = 0;
                    _DAT_108aefab8 = 0;
                    uRam0000000108aefad0 = 0;
                    _DAT_108aefac8 = 0;
                    DAT_108aefb68 = 0;
                    DAT_108aefb70 = 0;
                    DAT_108aefb60 = 0x68000000;
                    DAT_108aefa98 = &DAT_108aefaa0;
                    _atexit(&__ZN2ls13MemoryManager6AtExitEv);
                  }
                  if (lVar20 != 0) {
                    _free(lVar20);
                  }
                  if (DAT_108aefa98 == (undefined *)0x0) {
                    uRam0000000108aefaa8 = uVar6;
                    _DAT_108aefaa0 = uVar5;
                    DAT_108aefab0 = 4000;
                    DAT_108aefb58 = 0;
                    uRam0000000108aefac0 = 0;
                    _DAT_108aefab8 = 0;
                    uRam0000000108aefad0 = 0;
                    _DAT_108aefac8 = 0;
                    DAT_108aefb68 = 0;
                    DAT_108aefb70 = 0;
                    DAT_108aefb60 = 0x68000000;
                    DAT_108aefa98 = &DAT_108aefaa0;
                    _atexit(&__ZN2ls13MemoryManager6AtExitEv);
                  }
                  local_328 = 0;
                  lVar20 = 0;
                }
                local_330 = lVar20;
                if (DAT_108aefa98 == (undefined *)0x0) {
                  uRam0000000108aefaa8 = uVar6;
                  _DAT_108aefaa0 = uVar5;
                  DAT_108aefab0 = 4000;
                  DAT_108aefb58 = 0;
                  uRam0000000108aefac0 = 0;
                  _DAT_108aefab8 = 0;
                  uRam0000000108aefad0 = 0;
                  _DAT_108aefac8 = 0;
                  DAT_108aefb68 = 0;
                  DAT_108aefb70 = 0;
                  DAT_108aefb60 = 0x68000000;
                  DAT_108aefa98 = &DAT_108aefaa0;
                  _atexit(&__ZN2ls13MemoryManager6AtExitEv);
                }
                if (lVar20 != 0) {
                  _free(lVar20);
                }
                __ZN2ls7VariantIJN3eoc9interrupt14SpellCastEventENS2_12CastHitEventENS2_14SpellRollEventENS2_20ConditionalRollEventENS2_21LeaveAttackRangeEventENS2_21EnterAttackRangeEventENS2_19SpellPreDamageEventENS2_25PlaceholderSpellRollEventENS2_20ConditionResultEventENS2_18StatusAppliedEventENS2_10DeathEventENS2_10DebugEventEEE7Storage7DestroyIJLi0ELi1ELi2ELi3ELi4ELi5ELi6ELi7ELi8ELi9ELi10ELi11EEEEvNSt3__116integer_sequenceIiJXspT_EEEE
                          (&local_400);
                if (local_720 != -1) {
                  local_400 = CONCAT44(local_400._4_4_,local_720);
                  __ZN2ls3gst3Map7ReleaseERKNS0_12NodePoolDataE
                            (__ZN2ls3gst10s_InstanceE + 0xc600,&local_400);
                }
                if (local_758 != -1) {
                  local_400 = CONCAT44(local_400._4_4_,local_758);
                  __ZN2ls3gst3Map7ReleaseERKNS0_12NodePoolDataE
                            (__ZN2ls3gst10s_InstanceE + 0xc600,&local_400);
                }
              }
              else {
                uVar16 = *param_6;
                local_d0 = param_6[2];
                uStack_d8 = param_6[1];
                local_c8 = 1;
                uStack_78 = 0;
                uStack_80 = 0;
                uStack_68 = 0;
                local_70 = 0;
                uStack_58 = 0;
                uStack_60 = 0;
                uStack_48 = 0;
                local_50 = 0;
                uStack_38 = 0;
                uStack_40 = 0;
                uStack_28 = 0;
                local_30 = 0;
                local_20 = 0;
                uStack_a8 = 0;
                local_b0 = 0;
                uStack_98 = 0;
                uStack_a0 = 0;
                local_b8 = 0xffc0000000000000;
                local_c0 = &UNK_108809448;
                uStack_88 = 0xffc0000000000000;
                local_90 = &UNK_10880c4e0;
                if ((char)param_6[0x11] != '\0') {
                  local_c8 = param_6[0xe];
                }
                local_e0 = uVar16;
                func_0x0001010e0998(&local_778,param_7 + 2);
                lVar20 = param_2[4];
                if (*(int *)(lVar20 + 0x10) != 0) {
                  lVar19 = *(long *)(param_3 + 0x40);
                  uVar11 = __ZNK2ls11FixedString7GetHashEv(*(undefined4 *)(lVar19 + 0x40));
                  uVar2 = *(uint *)(lVar20 + 0x10);
                  uVar4 = 0;
                  if (uVar2 != 0) {
                    uVar4 = uVar11 / uVar2;
                  }
                  uVar2 = *(uint *)(*(long *)(lVar20 + 8) + (long)(int)(uVar11 - uVar4 * uVar2) * 4)
                  ;
                  if (-1 < (int)uVar2) {
                    do {
                      uVar22 = (ulong)uVar2;
                      if (*(int *)(*(long *)(lVar20 + 0x28) + uVar22 * 4) == *(int *)(lVar19 + 0x40)
                         ) {
                        lVar20 = *(long *)(*(long *)(lVar20 + 0x38) + uVar22 * 8);
                        if (lVar20 != 0) {
                          func_0x0001056a26a8(param_1,param_3,lVar20,in_stack_00000088,&local_778);
                        }
                        break;
                      }
                      uVar2 = *(uint *)(*(long *)(lVar20 + 0x18) + uVar22 * 4);
                    } while (-1 < (int)uVar2);
                  }
                }
                if ((char)param_6[0x11] == '\0') {
                  uVar22 = uVar16 >> 0x36;
                  puVar17 = (ulong *)0x0;
                  uVar24 = 0;
                  uVar2 = (uint)(uVar16 >> 0x20);
                  if ((uVar2 >> 0x16 < 0x41) && (uVar16 != 0xffc0000000000000)) {
                    lVar20 = *param_1;
                    uVar4 = *(uint *)
                             PTR___ZN2ls6TypeIdINS_18TransformComponentEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE_1083d25f0
                    ;
                    puVar14 = (ulong *)__ZNK3ecs6legacy19ImmediateWorldCache9GetChangeEN2ls2IDINS_18EntityHandleTraitsEEENS_11ComponentIdE
                                                 (*(undefined8 *)(lVar20 + 0x3f0),uVar16,
                                                  (ulong)uVar4 & 0x7fff);
                    if (puVar14 == (ulong *)0x0) {
                      plVar18 = *(long **)(lVar20 + 0x2d0);
                      uVar11 = (uint)uVar16;
                      if ((int)uVar11 < *(int *)((long)plVar18 + uVar22 * 0x10 + 0x5c)) {
                        lVar19 = *(long *)(plVar18[uVar22 * 2 + 10] +
                                          (long)((int)uVar11 >>
                                                (*(ushort *)(plVar18 + uVar22 * 2 + 0xb) & 0x1f)) *
                                          8);
                        uVar11 = uVar11 & (-1 << (ulong)(*(ushort *)(plVar18 + uVar22 * 2 + 0xb) &
                                                        0x1f) ^ 0xffffffffU);
                        if (*(uint *)(lVar19 + (-(ulong)(uVar11 >> 0x1f) & 0xfffffff800000000 |
                                               (ulong)uVar11 << 3)) == (uVar2 & 0x3fffff)) {
                          uVar22 = *(ulong *)(*(long *)(*plVar18 +
                                                       (ulong)*(ushort *)
                                                               (lVar19 + (long)(int)uVar11 * 8 + 4)
                                                       * 8) + ((ulong)(uVar4 >> 6) & 0x1ff) * 8) >>
                                   ((ulong)uVar4 & 0x3f) & 1;
                          goto joined_r0x00010538f26c;
                        }
                      }
                    }
                    else {
                      uVar22 = *puVar14;
joined_r0x00010538f26c:
                      if (uVar22 != 0) {
                        lVar20 = __ZN3ecs11EntityWorld12GetComponentIKN2ls18TransformComponentELb1EEEPT_NS2_2IDINS_18EntityHandleTraitsEEENSt3__117integral_constantIbLb0EEE
                                           (lVar20,uVar16);
                        puVar17 = *(ulong **)(lVar20 + 0x10);
                        uVar24 = *(undefined4 *)(lVar20 + 0x18);
                      }
                    }
                  }
                  local_780 = CONCAT44(local_780._4_4_,uVar24);
                  local_788 = puVar17;
                }
                else {
                  local_780 = CONCAT44(local_780._4_4_,(int)param_6[0x10]);
                  local_788 = (ulong *)param_6[0xf];
                }
                func_0x0001056a2180(&local_400,param_1,param_2,param_3,&local_e0,&local_788,
                                    &local_778,in_stack_00000088);
                func_0x000105782a24(&local_5b0,&local_400,*param_1,auStack_2c0,auStack_118);
                local_5c0 = local_5c0 & 0xffffffffffffff00;
                (**(code **)(*(long *)*param_2 + 0xf0))
                          ((long *)*param_2,iVar1,param_2,&local_590,&local_5c0);
                cVar9 = (char)local_5c0;
                func_0x0001010df3c0(&local_590);
                func_0x0001010df094(&local_400);
                __ZN3eoc7HitDescD2Ev(&local_778);
                uStack_d8 = uRam0000000108a6fcc8;
                local_e0 = ___ZN3eoc9interrupt10Dependency4NoneE;
                local_d0 = uRam0000000108a6fcd0;
                if (cVar9 != '\0') goto LAB_10538ed88;
              }
              puVar17 = &local_e0;
            }
            ProcessDealDamageFunctors
                      (param_1,lVar13,param_5,&local_5d0,param_8,in_stack_00000070,
                       (long)param_7 + 0x56,(long)param_7 + 0x57,puVar17,in_stack_00000078,
                       in_stack_00000080,in_stack_00000090);
          }
        }
        lVar23 = lVar23 + 1;
      } while (lVar23 != lVar12);
    }
  }
  if (*(long *)PTR____stack_chk_guard_1084028b8 == local_18) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

