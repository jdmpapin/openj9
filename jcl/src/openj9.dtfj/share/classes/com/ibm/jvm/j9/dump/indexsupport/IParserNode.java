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
package com.ibm.jvm.j9.dump.indexsupport;

import org.xml.sax.Attributes;

public interface IParserNode
{
	/**
	 * Called when a start tag is parsed.  Returns the node to handle this new scope which may be the same instance
	 * as the receiver if this same node wants to take responsibility.
	 * 
	 * @param uri
	 * @param localName
	 * @param qName
	 * @param attributes
	 * @return
	 */
	public IParserNode nodeToPushAfterStarting(String uri, String localName, String qName, Attributes attributes);
	
	/**
	 * Called when a literal string is parsed in the XML stream.
	 * 
	 * @param string
	 */
	public void stringWasParsed(String string);
	
	/**
	 * Called when this tag is done being parsed (the start tag and all children have been fully parsed) and it is
	 * going to be discarded by the parser.
	 */
	public void didFinishParsing();
}
