; ModuleID = 'bpf/sockstats.bpf.c'
source_filename = "bpf/sockstats.bpf.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.trace_event_raw_sys_enter = type { %struct.trace_entry, i64, [6 x i64], [0 x i8] }
%struct.trace_entry = type { i16, i8, i8, i32 }

@LICENSE = dso_local global [13 x i8] c"Dual BSD/GPL\00", section "license", align 1, !dbg !0
@llvm.compiler.used = appending global [2 x i8*] [i8* getelementptr inbounds ([13 x i8], [13 x i8]* @LICENSE, i32 0, i32 0), i8* bitcast (i32 (%struct.trace_event_raw_sys_enter*)* @tracepoint__syscalls__sys_enter_openat to i8*)], section "llvm.metadata"

; Function Attrs: mustprogress nofree norecurse nosync nounwind readnone willreturn
define dso_local i32 @tracepoint__syscalls__sys_enter_openat(%struct.trace_event_raw_sys_enter* nocapture readnone %0) #0 section "tracepoint/syscalls/sys_enter_openat" !dbg !14 {
  call void @llvm.dbg.value(metadata %struct.trace_event_raw_sys_enter* undef, metadata !43, metadata !DIExpression()), !dbg !44
  ret i32 0, !dbg !45
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

attributes #0 = { mustprogress nofree norecurse nosync nounwind readnone willreturn "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!9, !10, !11, !12}
!llvm.ident = !{!13}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "LICENSE", scope: !2, file: !3, line: 7, type: !5, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "bpf/sockstats.bpf.c", directory: "/home/jalal/sock-stats/src", checksumkind: CSK_MD5, checksum: "d51754b50dc3dc6874b990caf459025a")
!4 = !{!0}
!5 = !DICompositeType(tag: DW_TAG_array_type, baseType: !6, size: 104, elements: !7)
!6 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!7 = !{!8}
!8 = !DISubrange(count: 13)
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{i32 7, !"frame-pointer", i32 2}
!13 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!14 = distinct !DISubprogram(name: "tracepoint__syscalls__sys_enter_openat", scope: !3, file: !3, line: 11, type: !15, scopeLine: 12, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !42)
!15 = !DISubroutineType(types: !16)
!16 = !{!17, !18}
!17 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!18 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !19, size: 64)
!19 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "trace_event_raw_sys_enter", file: !20, line: 87889, size: 512, elements: !21)
!20 = !DIFile(filename: "bpf/vmlinux.h", directory: "/home/jalal/sock-stats/src", checksumkind: CSK_MD5, checksum: "bc04eb634f02736640eac9f57d8b6aad")
!21 = !{!22, !31, !33, !38}
!22 = !DIDerivedType(tag: DW_TAG_member, name: "ent", scope: !19, file: !20, line: 87890, baseType: !23, size: 64)
!23 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "trace_entry", file: !20, line: 5830, size: 64, elements: !24)
!24 = !{!25, !27, !29, !30}
!25 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !23, file: !20, line: 5831, baseType: !26, size: 16)
!26 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!27 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !23, file: !20, line: 5832, baseType: !28, size: 8, offset: 16)
!28 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!29 = !DIDerivedType(tag: DW_TAG_member, name: "preempt_count", scope: !23, file: !20, line: 5833, baseType: !28, size: 8, offset: 24)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "pid", scope: !23, file: !20, line: 5834, baseType: !17, size: 32, offset: 32)
!31 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !19, file: !20, line: 87891, baseType: !32, size: 64, offset: 64)
!32 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!33 = !DIDerivedType(tag: DW_TAG_member, name: "args", scope: !19, file: !20, line: 87892, baseType: !34, size: 384, offset: 128)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !35, size: 384, elements: !36)
!35 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!36 = !{!37}
!37 = !DISubrange(count: 6)
!38 = !DIDerivedType(tag: DW_TAG_member, name: "__data", scope: !19, file: !20, line: 87893, baseType: !39, offset: 512)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !6, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 0)
!42 = !{!43}
!43 = !DILocalVariable(name: "ctx", arg: 1, scope: !14, file: !3, line: 11, type: !18)
!44 = !DILocation(line: 0, scope: !14)
!45 = !DILocation(line: 29, column: 5, scope: !14)
