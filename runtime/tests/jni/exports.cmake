################################################################################
# Copyright (c) 2019, 2022 IBM Corp. and others
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License 2.0 which accompanies this
# distribution and is available at https://www.eclipse.org/legal/epl-2.0/
# or the Apache License, Version 2.0 which accompanies this distribution and
# is available at https://www.apache.org/licenses/LICENSE-2.0.
#
# This Source Code may also be made available under the following
# Secondary Licenses when the conditions for such availability set
# forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
# General Public License, version 2 with the GNU Classpath
# Exception [1] and GNU General Public License, version 2 with the
# OpenJDK Assembly Exception [2].
#
# [1] https://www.gnu.org/software/classpath/license.html
# [2] https://openjdk.org/legal/assembly-exception.html
#
# SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
################################################################################

omr_add_exports(j9ben
	JNI_OnLoad
	JNI_OnUnload
	Java_j9vm_test_jni_GetObjectRefTypeTest_getObjectRefTypeTest
	Java_jvmti_test_nativeMethodPrefixes_UnwrappedNative_nat
	Java_jvmti_test_nativeMethodPrefixes_DirectNative_gac4gac3gac2gac1nat
	Java_jvmti_test_nativeMethodPrefixes_WrappedNative_nat
	Java_jit_test_vich_JNIObjectArray_getObjectArrayElement
	Java_jit_test_vich_JNILocalRef_localReference32
	Java_jit_test_vich_JNILocalRef_localReference8
	Java_jit_test_vich_JNIArray_getPrimitiveArrayCritical
	Java_jit_test_vich_JNIArray_getDoubleArrayElements
	Java_jit_test_vich_JNIArray_getLongArrayElements
	Java_jit_test_vich_JNIArray_getFloatArrayElements
	Java_jit_test_vich_JNIArray_getByteArrayElements
	Java_jit_test_vich_JNIArray_getIntArrayElements
	Java_jit_test_vich_JNI_nativeJNI__III
	Java_jit_test_vich_JNI_nativeJNI__IIIII
	Java_jit_test_vich_JNI_nativeJNI__II
	Java_jit_test_vich_JNI_nativeJNI__I
	Java_jit_test_vich_JNI_nativeJNI__IIII
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__IIIIIIII
	Java_jit_test_vich_JNI_nativeJNI__IIIIIII
	Java_jit_test_vich_JNI_nativeJNI__IIIIII
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2Ljava_lang_Object_2
	Java_jit_test_vich_JNI_nativeJNI__
	Java_jit_test_vich_JNICallIn_callInVirtualVoid
	Java_jit_test_vich_JNICallIn_callInVirtualVoidA
	Java_jit_test_vich_JNICallIn_callInVirtualBoolean
	Java_jit_test_vich_JNICallIn_callInVirtualBooleanA
	Java_jit_test_vich_JNICallIn_callInVirtualByte
	Java_jit_test_vich_JNICallIn_callInVirtualByteA
	Java_jit_test_vich_JNICallIn_callInVirtualShort
	Java_jit_test_vich_JNICallIn_callInVirtualShortA
	Java_jit_test_vich_JNICallIn_callInVirtualChar
	Java_jit_test_vich_JNICallIn_callInVirtualCharA
	Java_jit_test_vich_JNICallIn_callInVirtualInt
	Java_jit_test_vich_JNICallIn_callInVirtualIntA
	Java_jit_test_vich_JNICallIn_callInVirtualLong
	Java_jit_test_vich_JNICallIn_callInVirtualLongA
	Java_jit_test_vich_JNICallIn_callInVirtualDouble
	Java_jit_test_vich_JNICallIn_callInVirtualDoubleA
	Java_jit_test_vich_JNICallIn_callInVirtualFloat
	Java_jit_test_vich_JNICallIn_callInVirtualFloatA
	Java_jit_test_vich_JNICallIn_callInVirtualObject
	Java_jit_test_vich_JNICallIn_callInVirtualObjectA
	Java_jit_test_vich_JNICallIn_callInNonvirtualVoid
	Java_jit_test_vich_JNICallIn_callInNonvirtualVoidA
	Java_jit_test_vich_JNICallIn_callInNonvirtualBoolean
	Java_jit_test_vich_JNICallIn_callInNonvirtualBooleanA
	Java_jit_test_vich_JNICallIn_callInNonvirtualByte
	Java_jit_test_vich_JNICallIn_callInNonvirtualByteA
	Java_jit_test_vich_JNICallIn_callInNonvirtualShort
	Java_jit_test_vich_JNICallIn_callInNonvirtualShortA
	Java_jit_test_vich_JNICallIn_callInNonvirtualChar
	Java_jit_test_vich_JNICallIn_callInNonvirtualCharA
	Java_jit_test_vich_JNICallIn_callInNonvirtualInt
	Java_jit_test_vich_JNICallIn_callInNonvirtualIntA
	Java_jit_test_vich_JNICallIn_callInNonvirtualLong
	Java_jit_test_vich_JNICallIn_callInNonvirtualLongA
	Java_jit_test_vich_JNICallIn_callInNonvirtualDouble
	Java_jit_test_vich_JNICallIn_callInNonvirtualDoubleA
	Java_jit_test_vich_JNICallIn_callInNonvirtualFloat
	Java_jit_test_vich_JNICallIn_callInNonvirtualFloatA
	Java_jit_test_vich_JNICallIn_callInNonvirtualObject
	Java_jit_test_vich_JNICallIn_callInNonvirtualObjectA
	Java_jit_test_vich_JNICallIn_callInStaticVoid
	Java_jit_test_vich_JNICallIn_callInStaticVoidA
	Java_jit_test_vich_JNICallIn_callInStaticBoolean
	Java_jit_test_vich_JNICallIn_callInStaticBooleanA
	Java_jit_test_vich_JNICallIn_callInStaticByte
	Java_jit_test_vich_JNICallIn_callInStaticByteA
	Java_jit_test_vich_JNICallIn_callInStaticShort
	Java_jit_test_vich_JNICallIn_callInStaticShortA
	Java_jit_test_vich_JNICallIn_callInStaticChar
	Java_jit_test_vich_JNICallIn_callInStaticCharA
	Java_jit_test_vich_JNICallIn_callInStaticInt
	Java_jit_test_vich_JNICallIn_callInStaticIntA
	Java_jit_test_vich_JNICallIn_callInStaticLong
	Java_jit_test_vich_JNICallIn_callInStaticLongA
	Java_jit_test_vich_JNICallIn_callInStaticDouble
	Java_jit_test_vich_JNICallIn_callInStaticDoubleA
	Java_jit_test_vich_JNICallIn_callInStaticFloat
	Java_jit_test_vich_JNICallIn_callInStaticFloatA
	Java_jit_test_vich_JNICallIn_callInStaticObject
	Java_jit_test_vich_JNICallIn_callInStaticObjectA
	Java_jit_test_vich_JNIFields_setStaticBoolean
	Java_jit_test_vich_JNIFields_getStaticBoolean
	Java_jit_test_vich_JNIFields_setStaticByte
	Java_jit_test_vich_JNIFields_getStaticByte
	Java_jit_test_vich_JNIFields_setStaticShort
	Java_jit_test_vich_JNIFields_getStaticShort
	Java_jit_test_vich_JNIFields_setStaticChar
	Java_jit_test_vich_JNIFields_getStaticChar
	Java_jit_test_vich_JNIFields_setStaticInt
	Java_jit_test_vich_JNIFields_getStaticInt
	Java_jit_test_vich_JNIFields_setStaticLong
	Java_jit_test_vich_JNIFields_getStaticLong
	Java_jit_test_vich_JNIFields_setStaticDouble
	Java_jit_test_vich_JNIFields_getStaticDouble
	Java_jit_test_vich_JNIFields_setStaticFloat
	Java_jit_test_vich_JNIFields_getStaticFloat
	Java_jit_test_vich_JNIFields_setStaticObject
	Java_jit_test_vich_JNIFields_getStaticObject
	Java_jit_test_vich_JNIFields_setInstanceBoolean
	Java_jit_test_vich_JNIFields_getInstanceBoolean
	Java_jit_test_vich_JNIFields_setInstanceByte
	Java_jit_test_vich_JNIFields_getInstanceByte
	Java_jit_test_vich_JNIFields_setInstanceShort
	Java_jit_test_vich_JNIFields_getInstanceShort
	Java_jit_test_vich_JNIFields_setInstanceChar
	Java_jit_test_vich_JNIFields_getInstanceChar
	Java_jit_test_vich_JNIFields_setInstanceInt
	Java_jit_test_vich_JNIFields_getInstanceInt
	Java_jit_test_vich_JNIFields_setInstanceLong
	Java_jit_test_vich_JNIFields_getInstanceLong
	Java_jit_test_vich_JNIFields_setInstanceDouble
	Java_jit_test_vich_JNIFields_getInstanceDouble
	Java_jit_test_vich_JNIFields_setInstanceFloat
	Java_jit_test_vich_JNIFields_getInstanceFloat
	Java_jit_test_vich_JNIFields_setInstanceObject
	Java_jit_test_vich_JNIFields_getInstanceObject
	Java_j9vm_test_jni_JNIFloatTest_floatJNITest
	Java_j9vm_test_jni_JNIMultiFloatTest_floatJNITest2
	Java_j9vm_test_jni_LocalRefTest_testPushLocalFrame1
	Java_j9vm_test_jni_LocalRefTest_testPushLocalFrame2
	Java_j9vm_test_jni_LocalRefTest_testPushLocalFrame3
	Java_j9vm_test_jni_LocalRefTest_testPushLocalFrame4
	Java_j9vm_test_jni_LocalRefTest_testPushLocalFrameNeverPop
	Java_j9vm_test_libraryhandle_LibHandleTest_libraryHandleTest
	Java_j9vm_test_libraryhandle_MultipleLibraryLoadTest_vmVersion
	Java_j9vm_test_jni_VolatileTest_getVolatileInt
	Java_j9vm_test_jni_VolatileTest_getVolatileFloat
	Java_j9vm_test_jni_VolatileTest_getVolatileLong
	Java_j9vm_test_jni_VolatileTest_getVolatileDouble
	Java_j9vm_test_jni_VolatileTest_getVolatileStaticDouble
	Java_j9vm_test_jni_VolatileTest_getVolatileStaticLong
	Java_j9vm_test_jni_VolatileTest_getVolatileStaticInt
	Java_j9vm_test_jni_VolatileTest_getVolatileStaticFloat
	Java_j9vm_test_jni_VolatileTest_setVolatileInt
	Java_j9vm_test_jni_VolatileTest_setVolatileFloat
	Java_j9vm_test_jni_VolatileTest_setVolatileLong
	Java_j9vm_test_jni_VolatileTest_setVolatileDouble
	Java_j9vm_test_jni_VolatileTest_setVolatileStaticDouble
	Java_j9vm_test_jni_VolatileTest_setVolatileStaticLong
	Java_j9vm_test_jni_VolatileTest_setVolatileStaticInt
	Java_j9vm_test_jni_VolatileTest_setVolatileStaticFloat
	Java_j9vm_test_jni_NullRefTest_test
	Java_j9vm_test_jnichk_BufferOverrun_test
	Java_j9vm_test_jnichk_ModifiedBuffer_test
	Java_j9vm_test_jnichk_DeleteGlobalRefTwice_test
	Java_j9vm_test_jnichk_ModifyArrayData_test
	Java_j9vm_test_jnichk_ConcurrentGlobalReferenceModification_test
	Java_j9vm_test_jnichk_ReturnInvalidReference_deletedGlobalRef
	Java_j9vm_test_jnichk_ReturnInvalidReference_deletedLocalRef
	Java_j9vm_test_jnichk_ReturnInvalidReference_explicitReturnOfNull
	Java_j9vm_test_jnichk_ReturnInvalidReference_localRefFromPoppedFrame
	Java_j9vm_test_jnichk_ReturnInvalidReference_validGlobalRef
	Java_j9vm_test_jnichk_ReturnInvalidReference_validLocalRef
	Java_j9vm_test_jnichk_CriticalAlwaysCopy_testArray
	Java_j9vm_test_jnichk_CriticalAlwaysCopy_testString
	Java_j9vm_test_jnichk_PassingFieldID_testToReflectedFieldExpectedStaticGotNonStatic
	Java_j9vm_test_jnichk_PassingFieldID_testToReflectedFieldExpectedNonStaticGotStatic
	Java_j9vm_test_jnichk_PassingFieldID_testGetCharFieldPassedStaticID
	Java_j9vm_test_jnichk_PassingFieldID_testGetStaticCharFieldPassedNonStaticID
	Java_j9vm_test_jnichk_PassingFieldID_testSetObjectFieldPassedStaticID
	Java_j9vm_test_jnichk_PassingFieldID_testSetStaticObjectFieldPassedNonStaticID
	Java_j9vm_test_monitor_Helpers_getLastReturnCode
	Java_j9vm_test_monitor_Helpers_monitorEnter
	Java_j9vm_test_monitor_Helpers_monitorExit
	Java_j9vm_test_monitor_Helpers_monitorExitWithException
	Java_j9vm_test_monitor_Helpers_monitorReserve
	Java_j9vm_test_memchk_NoFree_test
	Java_j9vm_test_memchk_BlockOverrun_test
	Java_j9vm_test_memchk_BlockUnderrun_test
	Java_j9vm_test_memchk_Generic_test
	Java_j9vm_test_thread_NativeHelpers_findDeadlockedThreads
	Java_j9vm_test_thread_NativeHelpers_findDeadlockedThreadsAndObjects
	Java_org_openj9_test_osthread_ReattachAfterExit_createTLSKeyDestructor
	Java_j9vm_test_classloading_VMAccess_getNumberOfNodes
	Java_com_ibm_jvmti_tests_util_TestRunner_callLoadAgentLibraryOnAttach
	Java_j9vm_utils_JNI_NewDirectByteBuffer
	Java_j9vm_utils_JNI_GetDirectBufferAddress
	Java_j9vm_utils_JNI_GetDirectBufferCapacity
	Java_com_ibm_j9_jnimark_Natives_getByteArrayElements
	Java_j9vm_test_jni_CriticalRegionTest_testGetRelease___3B
	Java_j9vm_test_jni_CriticalRegionTest_testModify___3BZ
	Java_j9vm_test_jni_CriticalRegionTest_testMemcpy___3B_3B
	Java_j9vm_test_jni_CriticalRegionTest_testGetRelease___3I
	Java_j9vm_test_jni_CriticalRegionTest_testModify___3IZ
	Java_j9vm_test_jni_CriticalRegionTest_testMemcpy___3I_3I
	Java_j9vm_test_jni_CriticalRegionTest_testGetRelease___3D
	Java_j9vm_test_jni_CriticalRegionTest_testModify___3DZ
	Java_j9vm_test_jni_CriticalRegionTest_testMemcpy___3D_3D
	Java_j9vm_test_jni_CriticalRegionTest_testGetRelease__Ljava_lang_String_2
	Java_j9vm_test_jni_CriticalRegionTest_testModify__Ljava_lang_String_2
	Java_j9vm_test_jni_CriticalRegionTest_testMemcpy__Ljava_lang_String_2Ljava_lang_String_2
	Java_j9vm_test_jni_CriticalRegionTest_holdsVMAccess
	Java_j9vm_test_jni_CriticalRegionTest_returnsDirectPointer
	Java_j9vm_test_jni_CriticalRegionTest_acquireAndSleep
	Java_j9vm_test_jni_CriticalRegionTest_acquireAndCallIn
	Java_j9vm_test_jni_CriticalRegionTest_acquireDiscardAndGC
	Java_j9vm_test_jni_Utf8Test_testAttachCurrentThreadAsDaemon
	Java_j9vm_test_memory_MemoryAllocator_allocateMemory
	Java_j9vm_test_memory_MemoryAllocator_allocateMemory32
	Java_j9vm_test_corehelper_DeadlockCoreGenerator_setup
	Java_j9vm_test_corehelper_DeadlockCoreGenerator_enterFirstMonitor
	Java_j9vm_test_corehelper_DeadlockCoreGenerator_enterSecondMonitor
	Java_j9vm_test_corehelper_DeadlockCoreGenerator_spawnNativeThread
	Java_j9vm_test_corehelper_DeadlockCoreGenerator_createNativeDeadlock
	Java_j9vm_test_jni_PthreadTest_attachAndDetach
	Java_org_openj9_test_contendedfields_FieldUtilities_getObjectAlignmentInBytes
	Java_org_openj9_test_jep425_VirtualThreadTests_lockSupportPark
)
