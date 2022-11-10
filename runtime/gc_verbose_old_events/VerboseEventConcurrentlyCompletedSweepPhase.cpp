
/*******************************************************************************
 * Copyright (c) 1991, 2014 IBM Corp. and others
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
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/

#include "j9.h"
#include "j9cfg.h"

#include "VerboseEventConcurrentlyCompletedSweepPhase.hpp"

#include "GCExtensions.hpp"
#include "VerboseManagerOld.hpp"

/**
 * Create an new instance of a MM_VerboseEventGlobalGCEnd event.
 * @param event Pointer to a structure containing the data passed over the hookInterface
 */
MM_VerboseEvent *
MM_VerboseEventConcurrentlyCompletedSweepPhase::newInstance(MM_ConcurrentlyCompletedSweepPhase *event, J9HookInterface** hookInterface)
{
	MM_VerboseEventConcurrentlyCompletedSweepPhase *eventObject;
	
	eventObject = (MM_VerboseEventConcurrentlyCompletedSweepPhase *)MM_VerboseEvent::create(event->currentThread, sizeof(MM_VerboseEventConcurrentlyCompletedSweepPhase));
	if(NULL != eventObject) {
		new(eventObject) MM_VerboseEventConcurrentlyCompletedSweepPhase(event, hookInterface);
		eventObject->initialize();
	}
	return eventObject;
}

void
MM_VerboseEventConcurrentlyCompletedSweepPhase::initialize(void)
{
	OMRPORT_ACCESS_FROM_OMRVMTHREAD(_omrThread);
	_timeInMilliSeconds = omrtime_current_time_millis();
}

/**
 * Populate events data fields.
 * The event calls the event stream requesting the address of events it is interested in.
 * When an address is returned it populates itself with the data.
 */
void
MM_VerboseEventConcurrentlyCompletedSweepPhase::consumeEvents(void)
{
}

/**
 * Passes a format string and data to the output routine defined in the passed output agent.
 * @param agent Pointer to an output agent.
 */
void
MM_VerboseEventConcurrentlyCompletedSweepPhase::formattedOutput(MM_VerboseOutputAgent *agent)
{
	OMRPORT_ACCESS_FROM_OMRVMTHREAD(_omrThread);
	char timestamp[32];
	UDATA indentLevel = _manager->getIndentLevel();
	
	omrstr_ftime(timestamp, sizeof(timestamp), VERBOSEGC_DATE_FORMAT, _timeInMilliSeconds);
	agent->formatAndOutput(static_cast<J9VMThread*>(_omrThread->_language_vmthread), indentLevel, "<con event=\"completed sweep\" timestamp=\"%s\">", timestamp);
	
	_manager->incrementIndent();
	indentLevel = _manager->getIndentLevel();
	
	agent->formatAndOutput(static_cast<J9VMThread*>(_omrThread->_language_vmthread), indentLevel, "<stats bytes=\"%zu\" time=\"%llu.%03.3llu\" />",
		_bytesSwept,
		_timeElapsed / 1000,
		_timeElapsed % 1000);
	
	_manager->decrementIndent();
	indentLevel = _manager->getIndentLevel();
	
	agent->formatAndOutput(static_cast<J9VMThread*>(_omrThread->_language_vmthread), indentLevel, "</con>");
	agent->endOfCycle(static_cast<J9VMThread*>(_omrThread->_language_vmthread));
}
