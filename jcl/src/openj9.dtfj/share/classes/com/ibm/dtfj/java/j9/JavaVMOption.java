/*[INCLUDE-IF Sidecar18-SE]*/
/*
 * Copyright IBM Corp. and others 2004
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
package com.ibm.dtfj.java.j9;

import com.ibm.dtfj.image.CorruptDataException;
import com.ibm.dtfj.image.DataUnavailable;
import com.ibm.dtfj.image.ImagePointer;

public class JavaVMOption implements com.ibm.dtfj.java.JavaVMOption {

	private String _optionString;
	private ImagePointer _extraInfo;
	
	public JavaVMOption(String optionString, ImagePointer extraInfo) {
		if (optionString == null) {
			throw new IllegalArgumentException();
		}
		_optionString = optionString;
		_extraInfo = extraInfo;
	}
	
	public String getOptionString() throws DataUnavailable, CorruptDataException {
		return _optionString;
	}

	public ImagePointer getExtraInfo() throws DataUnavailable, CorruptDataException {
		return _extraInfo;
	}

}
