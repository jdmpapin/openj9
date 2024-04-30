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
package com.ibm.uma.freemarker;

import com.ibm.uma.UMA;
import com.ibm.uma.UMAException;

import freemarker.template.SimpleScalar;
import freemarker.template.TemplateHashModel;
import freemarker.template.TemplateModel;
import freemarker.template.TemplateModelException;

public class Artifact implements TemplateHashModel {
	
	com.ibm.uma.om.Artifact artifact;
	
	public Artifact(String name) {
		artifact = UMA.getUma().getArtifact(name);
	}

	public Artifact(com.ibm.uma.om.Artifact artifact) {
		this.artifact = artifact;
	}

	public TemplateModel get(String arg0) throws TemplateModelException {
		try {
			if (arg0.equals("name")) {
				return new ArtifactName(artifact);
			}
			if (arg0.equals("data")) {
				return new ArtifactData(artifact);
			}
			if ( arg0.equals("targetNameWithRelease")) {
				return new SimpleScalar(UMA.getUma().getPlatform().getTargetNameWithRelease(artifact));
			}
			if ( arg0.equals("exportNames")) {
				return new ExportNames(artifact);
			}
			if ( arg0.equals("bundledArtifacts") ) {
				
				return new Artifacts(artifact.getAllArtifactsInThisBundleInHashtable());
			}
			TemplateModel platformExtension = com.ibm.uma.UMA.getUma().getPlatform().getDataModelExtension("uma.spec.flags."+artifact.getTargetName(), arg0);
			if (platformExtension!=null) return platformExtension;
			TemplateModel configurationExtension = com.ibm.uma.UMA.getUma().getConfiguration().getDataModelExtension("uma.spec.flags."+artifact.getTargetName(), arg0);
			if (configurationExtension!=null) return configurationExtension;
			return null;
		} catch (UMAException e) {
			throw new TemplateModelException(e);
		}
	}

	public boolean isEmpty() throws TemplateModelException {
		if ( artifact == null ) return true;
		return false;
	}

}
