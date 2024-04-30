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

package jit.test.recognizedMethod;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

public class TestJavaLangStrictMath {

    /**
    * Tests the constant corner cases defined by the {@link StrictMath.sqrt} method.
    * <p>
    * The JIT compiler will transform calls to {@link StrictMath.sqrt} within this test
    * into the following tree sequence:
    *
    * <code>
    * dsqrt
    *   dconst <x>
    * </code>
    *
    * Subsequent tree simplification passes will attempt to reduce this constant
    * operation to a <code>dsqrt</code> IL by performing the square root at compile
    * time. The transformation will be performed when the function get executed 
    * twice, therefore, the "invocationCount=2" is needed. However we must ensure the
    * result of the square root done by the compiler at compile time will be exactly 
    * the same as the result had it been done by the Java runtime at runtime. This 
    * test validates the results are the same.
    */
    @Test(groups = {"level.sanity"}, invocationCount=2)
    public void test_java_lang_StrictMath_sqrt() {
        AssertJUnit.assertTrue(Double.isNaN(StrictMath.sqrt(Double.NEGATIVE_INFINITY)));
        AssertJUnit.assertTrue(Double.isNaN(StrictMath.sqrt(-42.25d)));
        AssertJUnit.assertEquals(-0.0d, StrictMath.sqrt(-0.0d));
        AssertJUnit.assertEquals(+0.0d, StrictMath.sqrt(+0.0d));
        AssertJUnit.assertEquals(7.5d, StrictMath.sqrt(56.25d));
        AssertJUnit.assertEquals(Double.POSITIVE_INFINITY, StrictMath.sqrt(Double.POSITIVE_INFINITY));
        AssertJUnit.assertTrue(Double.isNaN(StrictMath.sqrt(Double.NaN)));
    }
}
