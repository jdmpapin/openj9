/*
 * Copyright IBM Corp. and others 2001
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
package jit.test.jitt.resolves;

import org.testng.annotations.Test;
import org.testng.Assert;

@Test(groups = { "level.sanity","component.jit" })
public class UnresolvedJavaStaticMethod extends jit.test.jitt.Test {

	private static boolean test = false;

	static boolean state() {
		return test;
	};
	static void setTrue() {
		test = true;
	}
	static void setFalse() {
		test = false;
	}

	static class X {
		public void tstFoo(int i) {
			if (UnresolvedJavaStaticMethod.state() != false)
				Assert.fail("unexpected state #2");
			if (i == 1) {
				UnresolvedJavaStaticMethod.setTrue();
				if (UnresolvedJavaStaticMethod.state() != true)
					Assert.fail("unexpected state #3");
				UnresolvedJavaStaticMethod.setFalse();
				if (UnresolvedJavaStaticMethod.state() != false)
					Assert.fail("unexpected state #4");
			}
		}
	}
	@Test
	public void testUnresolvedJavaStaticMethod() {
		X x = new X();
		for (int j = 0; j < sJitThreshold; j++) {
			x.tstFoo(0);
		}
		x.tstFoo(1);
	}

}
