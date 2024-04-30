/*
 * Copyright IBM Corp. and others 2023
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at https://www.eclipse.org/legal/epl-2.0/
 * or the Apache License, Version 2.0 which accompanies this distribution and
 * is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following
 * Secondary Licenses when the conditions for such availability set
 * forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
 * General Public License, version 2 with the GNU Classpath
 * Exception [1] and GNU General Public License, version 2 with the
 * OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] https://openjdk.org/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-2.0-only WITH OpenJDK-assembly-exception-1.0
 */
package org.openj9.test.lworld;

import org.objectweb.asm.*;

import static org.objectweb.asm.Opcodes.*;

public class ValueTypeGenerator extends ClassLoader {
	private static ValueTypeGenerator generator;

	static {
		generator = new ValueTypeGenerator();
	}

	private static class ClassConfiguration {
		private String name;
		private String superName;
		private String[] fields;
		private boolean isReference;
		private boolean hasNonStaticSynchronizedMethods;
		private int extraClassFlags;
		private ClassConfiguration accessedContainer;

		public ClassConfiguration(String name) {
			this.name = name;
			this.superName = "java/lang/Object";
		}

		public ClassConfiguration(String name, String[] fields) {
			this.name = name;
			this.superName = "java/lang/Object";
			this.fields = fields;
		}

		public String getName() {
			return name;
		}

		public String[] getFields() {
			return fields;
		}

		public void setIsReference(boolean isReference) {
			this.isReference = isReference;
			/* Only reference type can have non-static synchronized methods. Value type cannot have one. */
			setHasNonStaticSynchronizedMethods(isReference);
		}

		public boolean isReference() {
			return isReference;
		}

		public void setHasNonStaticSynchronizedMethods(boolean hasNonStaticSynchronizedMethods) {
			this.hasNonStaticSynchronizedMethods = hasNonStaticSynchronizedMethods;
		}

		public boolean hasNonStaticSynchronizedMethods() {
			return hasNonStaticSynchronizedMethods;
		}

		public void setSuperClassName(String superName) {
			this.superName = superName;
		}

		public String getSuperName() {
			return superName;
		}

		public void setExtraClassFlags(int extraClassFlags) {
			this.extraClassFlags = extraClassFlags;
		}

		public int getExtraClassFlags() {
			return extraClassFlags;
		}

		/**
		 * This method specifies a reference class - whose fields are expected to be of
		 * value types - an instance of which will be an argument to the
		 * {@code testUnresolvedValueTypePutField} and {@code testUnresolvedValueTypeGetField}
		 * methods that will be generated for the current class.  Those methods will perform
		 * {@code PUTFIELD} or {@code GETFIELD} operations, respectively, on the fields of
		 * the {@code accessedContainer} instance.
		 *
		 * The intention is to test delaying resolution of the fields and their types,
		 * particularly its effect on code generated by the JIT compiler.
		 */
		public void setAccessedContainer(ClassConfiguration accessedContainer) {
			this.accessedContainer = accessedContainer;
		}

		/**
		 * @see setAccessedContainer
		 */
		public ClassConfiguration getAccessedContainer() {
			return accessedContainer;
		}
	}

	public static Class<?> generateRefClass(String name) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name);
		classConfig.setIsReference(true);

		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateRefClass(String name, String[] fields) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name, fields);
		classConfig.setIsReference(true);

		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateRefClass(String name, String[] fields, String containerClassName, String[] containerFields) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name, fields);
		ClassConfiguration containerClassConfig = new ClassConfiguration(containerClassName, containerFields);
		containerClassConfig.setIsReference(true);
		classConfig.setAccessedContainer(containerClassConfig);
		classConfig.setIsReference(true);

		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateValueClass(String name) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name);

		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateValueClass(String name, String[] fields) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name, fields);

		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateValueClass(String name, String superClassName, String[] fields, int extraFlags) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name, fields);
		classConfig.setSuperClassName(superClassName);
		classConfig.setExtraClassFlags(extraFlags);
		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	public static Class<?> generateIllegalValueClassWithSynchMethods(String name, String[] fields) throws Throwable {
		ClassConfiguration classConfig = new ClassConfiguration(name, fields);
		classConfig.setHasNonStaticSynchronizedMethods(true);
		byte[] bytes = generateClass(classConfig);
		return generator.defineClass(name, bytes, 0, bytes.length);
	}

	private static byte[] generateClass(ClassConfiguration config) {
		String className = config.getName();
		String superName = config.getSuperName();
		String[] fields = config.getFields();
		boolean isRef = config.isReference();
		boolean addSyncMethods = config.hasNonStaticSynchronizedMethods();
		int extraClassFlags = config.getExtraClassFlags();

		ClassConfiguration containerClassConfig = config.getAccessedContainer();
		String containerUsedInCode = (containerClassConfig != null) ? containerClassConfig.getName() : null;
		String[] containerFields = (containerClassConfig != null) ? containerClassConfig.getFields() : null;


		ClassWriter cw = new ClassWriter(0);

		int classFlags = ACC_PUBLIC + ACC_FINAL + (isRef? ValhallaUtils.ACC_IDENTITY : ValhallaUtils.ACC_VALUE_TYPE) + extraClassFlags;
		cw.visit(ValhallaUtils.CLASS_FILE_MAJOR_VERSION, classFlags,
			className, null, superName, null);

		int makeMaxLocal = 0;
		String makeValueSig = "";
		String makeValueGenericSig = "";
		if (null != fields) {
			for (String s : fields) {
				String nameAndSigValue[] = s.split(":");
				int fieldModifiers = ACC_PUBLIC;
				if ((nameAndSigValue.length > 2) && nameAndSigValue[2].equals("static")) {
					fieldModifiers += ACC_STATIC;
				} else if (!isRef) {
					fieldModifiers += ACC_FINAL;
				}
				FieldVisitor fv = cw.visitField(fieldModifiers, nameAndSigValue[0], nameAndSigValue[1], null, null);
				if ((nameAndSigValue.length > 3) && nameAndSigValue[3].equals("NR")) {
					fv.visitAttribute(new ValhallaUtils.NullRestrictedAttribute());
				}
				fv.visitEnd();

				if ((nameAndSigValue.length <= 2) || !nameAndSigValue[2].equals("static")) {
					makeValueSig += nameAndSigValue[1];
					makeValueGenericSig += "Ljava/lang/Object;";
					if (nameAndSigValue[1].equals("J") || nameAndSigValue[1].equals("D")) {
						makeMaxLocal += 2;
					} else {
						makeMaxLocal += 1;
					}

					generateGetter(cw, nameAndSigValue, className);
					generateGetterGeneric(cw, nameAndSigValue, className);
				}
			}
		}

		addInit(cw);
		addMakeObject(cw, className);
		if (isRef) {
			addTestMonitorEnterAndExitWithRefType(cw);
			addTestMonitorExitOnObject(cw);
			addTestCheckCastRefClassOnNull(cw, className, fields);
			if (containerFields != null) {
				testUnresolvedValueTypePutField(cw, className, containerUsedInCode, containerFields);
				testUnresolvedValueTypeGetField(cw, className, containerUsedInCode, containerFields);
			}
		} else {
			/* make value classes eligble to be nullrestricted */
			cw.visitAttribute(new ValhallaUtils.ImplicitCreationAttribute());
			addTestCheckCastValueTypeOnNull(cw, className, fields);
		}
		addStaticMethod(cw);
		addStaticSynchronizedMethods(cw);
		addTestCheckCastOnInvalidClass(cw);
		if (addSyncMethods) {
			addSynchronizedMethods(cw);
		}
		return cw.toByteArray();
	}

	private static void addStaticMethod(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "staticMethod", "()V", null, null);
		mv.visitCode();
		mv.visitInsn(RETURN);
		mv.visitMaxs(1, 1);
		mv.visitEnd();
	}

	private static void addInit(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
		mv.visitInsn(RETURN);
		mv.visitMaxs(1, 1);
		mv.visitEnd();
	}

	private static void addMakeObject(ClassWriter cw, String className) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC  + ACC_STATIC, "makeObject", "()" + "L" + className + ";", null, null);
		mv.visitCode();
		mv.visitTypeInsn(NEW, className);
		mv.visitInsn(DUP);
		mv.visitMethodInsn(INVOKESPECIAL, className, "<init>", "()V");
		mv.visitVarInsn(ASTORE, 0);
		mv.visitVarInsn(ALOAD, 0);
		mv.visitInsn(ARETURN);
		mv.visitMaxs(2, 1);
		mv.visitEnd();
	}

	/*
	* This function should only be called in the
	* TestMonitorEnterAndExitWithRefType test
	*/
	private static void addTestMonitorEnterAndExitWithRefType(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testMonitorEnterAndExitWithRefType", "(Ljava/lang/Object;)V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitInsn(DUP);
		mv.visitInsn(MONITORENTER);
		mv.visitInsn(MONITOREXIT);
		mv.visitInsn(RETURN);
		mv.visitMaxs(2,1);
		mv.visitEnd();
	}

	private static void addStaticSynchronizedMethods(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC + ACC_SYNCHRONIZED, "staticSynchronizedMethodReturnInt", "()I", null, null);
		mv.visitCode();
		mv.visitInsn(ICONST_1);
		mv.visitInsn(IRETURN);
		mv.visitMaxs(1, 0);
		mv.visitEnd();
	}

	private static void addSynchronizedMethods(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_SYNCHRONIZED, "synchronizedMethodReturnInt", "()I", null, null);
		mv.visitCode();
		mv.visitInsn(ICONST_1);
		mv.visitInsn(IRETURN);
		mv.visitMaxs(1, 1);
		mv.visitEnd();
	}

	 /*
	  * This function should only be called in the
	  * TestMonitorExitOnValueType test and
	  * TestMonitorExitWithRefType test
	  */
	  private static void addTestMonitorExitOnObject(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testMonitorExitOnObject", "(Ljava/lang/Object;)V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitInsn(MONITOREXIT);
		mv.visitInsn(RETURN);
		mv.visitMaxs(1, 1);
		mv.visitEnd();
	}

	private static void addTestCheckCastRefClassOnNull(ClassWriter cw, String className, String[] fields) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testCheckCastRefClassOnNull", "()Ljava/lang/Object;", null, null);
		mv.visitCode();
		mv.visitInsn(ACONST_NULL);
		mv.visitTypeInsn(CHECKCAST, className);
		mv.visitInsn(ARETURN);
		mv.visitMaxs(1, 2);
		mv.visitEnd();
	}

	private static void addTestCheckCastValueTypeOnNull(ClassWriter cw, String className, String[] fields) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testCheckCastValueTypeOnNull", "()Ljava/lang/Object;", null, null);
		mv.visitCode();
		mv.visitInsn(ACONST_NULL);
		mv.visitTypeInsn(CHECKCAST, "L" + className + ";");
		mv.visitInsn(ARETURN);
		mv.visitMaxs(1, 2);
		mv.visitEnd();
	}

	private static void addTestCheckCastOnInvalidClass(ClassWriter cw) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testCheckCastOnInvalidClass", "()Ljava/lang/Object;", null, null);
		mv.visitCode();
		mv.visitInsn(ACONST_NULL);
		mv.visitTypeInsn(CHECKCAST, "ClassDoesNotExist");
		mv.visitInsn(ARETURN);
		mv.visitMaxs(1, 2);
		mv.visitEnd();
	}

	private static void testUnresolvedValueTypeGetField(ClassWriter cw, String className, String containerClassName, String[] containerFields) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testUnresolvedValueTypeGetField", "(IL"+containerClassName+";)Ljava/lang/Object;", null, null);
		mv.visitCode();
		mv.visitVarInsn(ILOAD, 0);
		int fieldCount = containerFields.length;
		Label endLabel = new Label();
		Label defaultLabel = new Label();
		Label[] caseLabels = new Label[fieldCount];
		for (int i = 0; i < fieldCount; i++) {
			caseLabels[i] = new Label();
		}
		mv.visitTableSwitchInsn(0, fieldCount-1, defaultLabel, caseLabels);
		for (int i = 0; i < fieldCount; i++) {
			String nameAndSigValue[] = containerFields[i].split(":");
			mv.visitLabel(caseLabels[i]);
			mv.visitFrame(F_SAME, 3, new Object[] {INTEGER, containerClassName, "Ljava/lang/Object;"}, 0, new Object[]{});
			mv.visitVarInsn(ALOAD, 1);
			mv.visitFieldInsn(GETFIELD, containerClassName, nameAndSigValue[0], nameAndSigValue[1]);
			mv.visitJumpInsn(GOTO, endLabel);
		}
		mv.visitLabel(defaultLabel);
		mv.visitFrame(F_SAME, 3, new Object[] {INTEGER, containerClassName, "Ljava/lang/Object;"}, 0, new Object[]{});
		mv.visitInsn(ACONST_NULL);
		mv.visitLabel(endLabel);
		mv.visitFrame(F_SAME1, 3, new Object[] {INTEGER, containerClassName, "Ljava/lang/Object;"}, 1, new Object[]{"Ljava/lang/Object;"});
		mv.visitInsn(ARETURN);
		mv.visitMaxs(1, 2);
		mv.visitEnd();
	}

	private static void testUnresolvedValueTypePutField(ClassWriter cw, String className, String containerClassName, String[] containerFields) {
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC + ACC_STATIC, "testUnresolvedValueTypePutField", "(IL"+containerClassName+";Ljava/lang/Object;)V", null, null);
		mv.visitCode();
		mv.visitVarInsn(ILOAD, 0);
		int fieldCount = containerFields.length;
		Label endLabel = new Label();
		Label defaultLabel = new Label();
		Label[] caseLabels = new Label[fieldCount];
		for (int i = 0; i < fieldCount; i++) {
			caseLabels[i] = new Label();
		}
		mv.visitTableSwitchInsn(0, fieldCount-1, defaultLabel, caseLabels);
		for (int i = 0; i < fieldCount; i++) {
			String nameAndSigValue[] = containerFields[i].split(":");
			mv.visitLabel(caseLabels[i]);
			mv.visitFrame(F_SAME, 3, new Object[] {INTEGER, containerClassName, "Ljava/lang/Object;"}, 0, new Object[]{});
			mv.visitVarInsn(ALOAD, 1);
			mv.visitVarInsn(ALOAD, 2);
			mv.visitTypeInsn(CHECKCAST, nameAndSigValue[1]);
			mv.visitFieldInsn(PUTFIELD, containerClassName, nameAndSigValue[0], nameAndSigValue[1]);
			mv.visitJumpInsn(GOTO, endLabel);
		}
		mv.visitLabel(defaultLabel);
		mv.visitLabel(endLabel);
		mv.visitFrame(F_SAME, 3, new Object[] {INTEGER, containerClassName, "Ljava/lang/Object;"}, 0, new Object[]{});
		mv.visitInsn(RETURN);
		mv.visitMaxs(2, 3);
		mv.visitEnd();
	}

	private static void generateGetterGeneric(ClassWriter cw, String[] nameAndSigValue, String className) {
		boolean doubleDetected = false;
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "getGeneric" + nameAndSigValue[0], "()Ljava/lang/Object;", null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitMethodInsn(INVOKEVIRTUAL, className, "get" + nameAndSigValue[0], "()" + nameAndSigValue[1], false);
		switch (nameAndSigValue[1]) {
		case "D":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false);
			doubleDetected = true;
			break;
		case "I":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
			break;
		case "Z":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false);
			break;
		case "B":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false);
			break;
		case "C":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false);
			break;
		case "S":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false);
			break;
		case "F":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false);
			break;
		case "J":
			mv.visitMethodInsn(INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false);
			doubleDetected = true;
			break;
		default:
			break;
		}

		mv.visitInsn(ARETURN);
		int maxStack = (doubleDetected ? 2 : 1);
		mv.visitMaxs(maxStack, 1);
		mv.visitEnd();
	}

	private static void generateGetter(ClassWriter cw, String[] nameAndSigValue, String className) {
		boolean doubleDetected = false;
		MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "get" + nameAndSigValue[0], "()" + nameAndSigValue[1], null, null);
		mv.visitCode();
		mv.visitVarInsn(ALOAD, 0);
		mv.visitFieldInsn(GETFIELD, className, nameAndSigValue[0], nameAndSigValue[1]);
		switch (nameAndSigValue[1]) {
		case "D":
			mv.visitInsn(DRETURN);
			doubleDetected = true;
			break;
		case "I":
		case "Z":
		case "B":
		case "C":
		case "S":
			mv.visitInsn(IRETURN);
			break;
		case "F":
			mv.visitInsn(FRETURN);
			break;
		case "J":
			mv.visitInsn(LRETURN);
			doubleDetected = true;
			break;
		default:
			mv.visitInsn(ARETURN);
			break;
		}
		int maxStack = (doubleDetected ? 2 : 1);
		mv.visitMaxs(maxStack, 1);
		mv.visitEnd();
	}
}
