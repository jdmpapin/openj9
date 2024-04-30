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
package com.ibm.jvmti.tests.decompResolveFrame;

public class decomp002 
{
	public native boolean singleStep();
	
	public boolean testStepping()
	{
		boolean ret;
		
		Thread [] threadList = new Thread[16];
		
		for (int i = 0; i < 16; i++) {
			fThread t = new fThread("Runner");
			t.start();
			threadList[i] = t;
		}
		
		ret = singleStep();
		
		return ret;
	}
	
	public String helpStepping()
	{
		return "Alternate between executing some code with single stepping on and off";
	}
	
}

