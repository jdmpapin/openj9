/*
 * Copyright IBM Corp. and others 2019
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

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.lang.reflect.Array;

import static org.openj9.test.lworld.ValueTypeTestClasses.*;

public class DDRValueTypeTest {
	public static void main(String[] args) {
		try {
			createAndCheckValueType();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}

	private static void createAndCheckValueType() throws Throwable {
		AssortedValueWithSingleAlignment assortedValueWithSingleAlignment =
			AssortedValueWithSingleAlignment.createObjectWithDefaults();
		AssortedValueWithSingleAlignment assortedValueWithSingleAlignmentAlt =
			new AssortedValueWithSingleAlignment(new Triangle2D(defaultTrianglePositionsNew),
				new Point2D(defaultPointPositions2),
				new FlattenedLine2D(defaultLinePositions2),
				new ValueInt(defaultIntNew), new ValueFloat(defaultFloatNew),
				new Triangle2D(defaultTrianglePositionsNew));

		AssortedValueWithSingleAlignment[] array = new AssortedValueWithSingleAlignment[2];
		array[0] = assortedValueWithSingleAlignment;
		array[1] = assortedValueWithSingleAlignmentAlt;

		ValueTypeTests.checkObject(assortedValueWithSingleAlignment,
				assortedValueWithSingleAlignmentAlt,
				array
				);
	}
}
