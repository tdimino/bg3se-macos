
/* WARNING: Removing unreachable block (ram,0x00010538f840) */
/* WARNING: Removing unreachable block (ram,0x00010538f81c) */
/* WARNING: Removing unreachable block (ram,0x00010538f864) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void ProcessDealDamageFunctors
               (long *param_1,long param_2,ulong *param_3,undefined8 *param_4,long param_5,
               undefined4 *param_6,undefined1 *param_7,undefined1 *param_8,undefined8 *param_9,
               undefined8 *param_10,uint param_11,undefined8 param_12)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  ulong *puVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  long *plVar10;
  long lVar11;
  ulong uVar12;
  long lVar13;
  uint uVar14;
  ulong uVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  undefined8 uVar19;
  undefined8 uVar20;
  undefined8 uVar21;
  undefined8 uVar22;
  undefined8 uVar23;
  undefined8 uVar24;
  undefined8 uVar25;
  undefined8 uVar26;
  undefined1 uStack_360;
  undefined4 local_2d8;
  undefined6 uStack_2ce;
  undefined7 uStack_2af;
  undefined1 uStack_2a8;
  undefined7 uStack_2a7;
  undefined1 uStack_2a0;
  undefined8 *local_250;
  undefined8 uStack_248;
  undefined8 local_240;
  undefined8 uStack_238;
  ulong local_230;
  undefined8 uStack_228;
  undefined8 local_220;
  undefined8 uStack_218;
  undefined8 uStack_210;
  undefined8 uStack_208;
  undefined8 local_200;
  undefined8 uStack_1f8;
  undefined1 uStack_1f0;
  undefined7 uStack_1ef;
  undefined1 uStack_1e8;
  undefined7 uStack_1e7;
  undefined1 local_1e0;
  undefined7 uStack_1df;
  ulong uStack_1d8;
  undefined8 local_1d0;
  undefined8 uStack_1c8;
  undefined8 local_1c0;
  undefined8 uStack_1b8;
  undefined8 local_1b0;
  ulong uStack_1a8;
  ulong local_1a0;
  undefined8 local_198;
  undefined1 local_190 [168];
  undefined1 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  ulong local_d0;
  undefined8 local_c8;
  long local_c0;
  int local_b8;
  int local_b4;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined1 local_90;
  undefined8 local_88;
  undefined8 uStack_80;
  long local_78;
  
  local_78 = *(long *)PTR____stack_chk_guard_1084028b8;
  if (*(char *)(param_2 + 0x45) != '\r') goto LAB_10538f87c;
  uVar4 = *(undefined1 *)(param_2 + 0x47);
  uVar21 = *(undefined8 *)(param_2 + 0x18);
  uVar16 = *(undefined8 *)(param_2 + 0x10);
  uVar1 = *(uint *)(param_5 + 0x40);
  if (uVar1 != 0xffffffff) {
    __ZN2ls3gst7AcquireEj(uVar1);
  }
  uVar22 = *(undefined8 *)(param_5 + 0xa8);
  uVar17 = *(undefined8 *)(param_5 + 0xa0);
  local_2d8 = CONCAT31(local_2d8._1_3_,uVar4);
  uVar2 = *param_6;
  uVar4 = *param_7;
  uVar5 = *param_8;
  uVar23 = param_9[1];
  uVar18 = *param_9;
  uVar8 = param_9[2];
  uStack_2a0 = (undefined1)param_10[2];
  uVar19 = *param_10;
  uStack_2a8 = (undefined1)param_10[1];
  uStack_2a7 = (undefined7)((ulong)param_10[1] >> 8);
  uStack_2af = (undefined7)((ulong)uVar19 >> 8);
  uVar3 = *(uint *)(param_5 + 0x10);
  if (uVar3 != 0xffffffff) {
    __ZN2ls3gst7AcquireEj(uVar3);
  }
  uVar24 = *(undefined8 *)(param_5 + 0x20);
  uVar20 = *(undefined8 *)(param_5 + 0x18);
  uVar26 = *(undefined8 *)(param_5 + 0x30);
  uVar25 = *(undefined8 *)(param_5 + 0x28);
  uVar9 = *(undefined8 *)(param_5 + 0x38);
  uVar14 = *(uint *)(param_5 + 0x40);
  if (uVar14 != 0xffffffff) {
    __ZN2ls3gst7AcquireEj(uVar14);
  }
  uStack_210 = CONCAT62(uStack_2ce,CONCAT11(uVar5,uVar4));
  uStack_218 = CONCAT44(uVar2,local_2d8);
  uStack_360 = (undefined1)uVar19;
  uStack_1df = 0;
  uStack_1e7 = uStack_2a7;
  local_1e0 = uStack_2a0;
  uStack_1e8 = uStack_2a8;
  local_e8 = 6;
  local_198 = 6;
  local_230 = (ulong)uVar1;
  uStack_1d8 = (ulong)uVar3;
  uStack_1a8 = (ulong)uVar14;
  uVar15 = *param_3;
  uVar12 = uVar15 >> 0x36;
  puVar7 = (undefined8 *)&__ZN2ls4Guid7s_EmptyE;
  local_1a0 = (ulong)param_11;
  uVar1 = (uint)(uVar15 >> 0x20);
  local_240 = uVar16;
  uStack_238 = uVar21;
  uStack_228 = uVar17;
  local_220 = uVar22;
  uStack_208 = uVar18;
  local_200 = uVar23;
  uStack_1f8 = uVar8;
  uStack_1f0 = uStack_360;
  uStack_1ef = uStack_2af;
  local_1d0 = uVar20;
  uStack_1c8 = uVar24;
  local_1c0 = uVar25;
  uStack_1b8 = uVar26;
  local_1b0 = uVar9;
  if ((uVar1 >> 0x16 < 0x41) && (uVar15 != 0xffc0000000000000)) {
    lVar13 = *param_1;
    uVar3 = *(uint *)
             PTR___ZN2ls6TypeIdINS_4uuid9ComponentEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE_1083d3290
    ;
    puVar6 = (ulong *)__ZNK3ecs6legacy19ImmediateWorldCache9GetChangeEN2ls2IDINS_18EntityHandleTraitsEEENS_11ComponentIdE
                                (*(undefined8 *)(lVar13 + 0x3f0),uVar15,(ulong)uVar3 & 0x7fff);
    if (puVar6 == (ulong *)0x0) {
      plVar10 = *(long **)(lVar13 + 0x2d0);
      uVar14 = (uint)uVar15;
      if ((int)uVar14 < *(int *)((long)plVar10 + uVar12 * 0x10 + 0x5c)) {
        lVar11 = *(long *)(plVar10[uVar12 * 2 + 10] +
                          (long)((int)uVar14 >> (*(ushort *)(plVar10 + uVar12 * 2 + 0xb) & 0x1f)) *
                          8);
        uVar14 = uVar14 & (-1 << (ulong)(*(ushort *)(plVar10 + uVar12 * 2 + 0xb) & 0x1f) ^
                          0xffffffffU);
        if (*(uint *)(lVar11 + (-(ulong)(uVar14 >> 0x1f) & 0xfffffff800000000 | (ulong)uVar14 << 3))
            == (uVar1 & 0x3fffff)) {
          uVar12 = *(ulong *)(*(long *)(*plVar10 +
                                       (ulong)*(ushort *)(lVar11 + (long)(int)uVar14 * 8 + 4) * 8) +
                             ((ulong)(uVar3 >> 6) & 0x1ff) * 8) >> ((ulong)uVar3 & 0x3f) & 1;
          goto joined_r0x00010538f634;
        }
      }
    }
    else {
      uVar12 = *puVar6;
joined_r0x00010538f634:
      if (uVar12 != 0) {
        puVar7 = (undefined8 *)
                 __ZN3ecs11EntityWorld12GetComponentIKN2ls4uuid9ComponentELb1EEEPT_NS2_2IDINS_18EntityHandleTraitsEEENSt3__117integral_constantIbLb0EEE
                           (lVar13,uVar15);
        local_e8 = (undefined1)local_198;
        goto LAB_10538f644;
      }
    }
    puVar7 = (undefined8 *)&__ZN2ls4Guid7s_EmptyE;
    local_e8 = 6;
  }
LAB_10538f644:
  uVar16 = *puVar7;
  uVar21 = puVar7[1];
  func_0x0001016f3550(local_190,&local_240);
  local_e0 = *(undefined8 *)(param_5 + 8);
  local_d8 = 0xffc0000000000000;
  local_d0 = *param_3;
  local_c8 = 0xffc0000000000000;
  local_250 = &local_88;
  uStack_248 = 1;
  local_88 = uVar16;
  uStack_80 = uVar21;
  func_0x00010537f02c(&local_c0,&local_250);
  uStack_a8 = *(undefined8 *)(param_5 + 0x68);
  local_b0 = *(undefined8 *)(param_5 + 0x60);
  uStack_98 = param_4[1];
  uStack_a0 = *param_4;
  local_90 = 0;
  __ZN2ls7VariantIJN3eoc9interrupt14SpellCastEventENS2_12CastHitEventENS2_14SpellRollEventENS2_20ConditionalRollEventENS2_21LeaveAttackRangeEventENS2_21EnterAttackRangeEventENS2_19SpellPreDamageEventENS2_25PlaceholderSpellRollEventENS2_20ConditionResultEventENS2_18StatusAppliedEventENS2_10DeathEventENS2_10DebugEventEEE7Storage7DestroyIJLi0ELi1ELi2ELi3ELi4ELi5ELi6ELi7ELi8ELi9ELi10ELi11EEEEvNSt3__116integer_sequenceIiJXspT_EEEE
            (&local_240);
  func_0x000105363464(param_12,local_190);
  lVar13 = local_c0;
  if (local_b8 != 0) {
    if (0 < local_b4) {
      local_b4 = 0;
    }
    if (DAT_108aefa98 == (undefined *)0x0) {
      uRam0000000108aefaa8 = _UNK_10783b018;
      _DAT_108aefaa0 = _DAT_10783b010;
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
    if (local_c0 != 0) {
      _free(local_c0);
    }
    if (DAT_108aefa98 == (undefined *)0x0) {
      uRam0000000108aefaa8 = _UNK_10783b018;
      _DAT_108aefaa0 = _DAT_10783b010;
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
    lVar13 = 0;
  }
  local_b8 = 0;
  local_c0 = lVar13;
  if (DAT_108aefa98 == (undefined *)0x0) {
    local_b8 = 0;
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
    _DAT_108aefaa0 = _DAT_10783b010;
    uRam0000000108aefaa8 = _UNK_10783b018;
    _atexit(&__ZN2ls13MemoryManager6AtExitEv);
  }
  if (lVar13 != 0) {
    _free(lVar13);
  }
  __ZN2ls7VariantIJN3eoc9interrupt14SpellCastEventENS2_12CastHitEventENS2_14SpellRollEventENS2_20ConditionalRollEventENS2_21LeaveAttackRangeEventENS2_21EnterAttackRangeEventENS2_19SpellPreDamageEventENS2_25PlaceholderSpellRollEventENS2_20ConditionResultEventENS2_18StatusAppliedEventENS2_10DeathEventENS2_10DebugEventEEE7Storage7DestroyIJLi0ELi1ELi2ELi3ELi4ELi5ELi6ELi7ELi8ELi9ELi10ELi11EEEEvNSt3__116integer_sequenceIiJXspT_EEEE
            (local_190);
LAB_10538f87c:
  if (*(long *)PTR____stack_chk_guard_1084028b8 == local_78) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

