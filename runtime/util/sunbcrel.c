/*******************************************************************************
 * Copyright (c) 1991, 2022 IBM Corp. and others
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

const unsigned char sunJavaByteCodeRelocation[] = {
0x01 /* JBnop = 0 */ ,
0x01 /* JBaconstnull = 1 */ ,
0x01 /* JBiconstm1 = 2 */ ,
0x01 /* JBiconst0 = 3 */ ,
0x01 /* JBiconst1 = 4 */ ,
0x01 /* JBiconst2 = 5 */ ,
0x01 /* JBiconst3 = 6 */ ,
0x01 /* JBiconst4 = 7 */ ,
0x01 /* JBiconst5 = 8 */ ,
0x01 /* JBlconst0 = 9 */ ,
0x01 /* JBlconst1 = 10 */ ,
0x01 /* JBfconst0 = 11 */ ,
0x01 /* JBfconst1 = 12 */ ,
0x01 /* JBfconst2 = 13 */ ,
0x01 /* JBdconst0 = 14 */ ,
0x01 /* JBdconst1 = 15 */ ,
0x02 /* JBbipush = 16 */ ,
0x0B /* JBsipush = 17 */ ,
0x02 /* JBldc = 18 */ ,
0x0B /* JBldcw = 19 */ ,
0x0B /* JBldc2w = 20 */ ,
0x02 /* JBiload = 21 */ ,
0x02 /* JBlload = 22 */ ,
0x02 /* JBfload = 23 */ ,
0x02 /* JBdload = 24 */ ,
0x02 /* JBaload = 25 */ ,
0x01 /* JBiload0 = 26 */ ,
0x01 /* JBiload1 = 27 */ ,
0x01 /* JBiload2 = 28 */ ,
0x01 /* JBiload3 = 29 */ ,
0x01 /* JBlload0 = 30 */ ,
0x01 /* JBlload1 = 31 */ ,
0x01 /* JBlload2 = 32 */ ,
0x01 /* JBlload3 = 33 */ ,
0x01 /* JBfload0 = 34 */ ,
0x01 /* JBfload1 = 35 */ ,
0x01 /* JBfload2 = 36 */ ,
0x01 /* JBfload3 = 37 */ ,
0x01 /* JBdload0 = 38 */ ,
0x01 /* JBdload1 = 39 */ ,
0x01 /* JBdload2 = 40 */ ,
0x01 /* JBdload3 = 41 */ ,
0x01 /* JBaload0 = 42 */ ,
0x01 /* JBaload1 = 43 */ ,
0x01 /* JBaload2 = 44 */ ,
0x01 /* JBaload3 = 45 */ ,
0x01 /* JBiaload = 46 */ ,
0x01 /* JBlaload = 47 */ ,
0x01 /* JBfaload = 48 */ ,
0x01 /* JBdaload = 49 */ ,
0x01 /* JBaaload = 50 */ ,
0x01 /* JBbaload = 51 */ ,
0x01 /* JBcaload = 52 */ ,
0x01 /* JBsaload = 53 */ ,
0x02 /* JBistore = 54 */ ,
0x02 /* JBlstore = 55 */ ,
0x02 /* JBfstore = 56 */ ,
0x02 /* JBdstore = 57 */ ,
0x02 /* JBastore = 58 */ ,
0x01 /* JBistore0 = 59 */ ,
0x01 /* JBistore1 = 60 */ ,
0x01 /* JBistore2 = 61 */ ,
0x01 /* JBistore3 = 62 */ ,
0x01 /* JBlstore0 = 63 */ ,
0x01 /* JBlstore1 = 64 */ ,
0x01 /* JBlstore2 = 65 */ ,
0x01 /* JBlstore3 = 66 */ ,
0x01 /* JBfstore0 = 67 */ ,
0x01 /* JBfstore1 = 68 */ ,
0x01 /* JBfstore2 = 69 */ ,
0x01 /* JBfstore3 = 70 */ ,
0x01 /* JBdstore0 = 71 */ ,
0x01 /* JBdstore1 = 72 */ ,
0x01 /* JBdstore2 = 73 */ ,
0x01 /* JBdstore3 = 74 */ ,
0x01 /* JBastore0 = 75 */ ,
0x01 /* JBastore1 = 76 */ ,
0x01 /* JBastore2 = 77 */ ,
0x01 /* JBastore3 = 78 */ ,
0x01 /* JBiastore = 79 */ ,
0x01 /* JBlastore = 80 */ ,
0x01 /* JBfastore = 81 */ ,
0x01 /* JBdastore = 82 */ ,
0x01 /* JBaastore = 83 */ ,
0x01 /* JBbastore = 84 */ ,
0x01 /* JBcastore = 85 */ ,
0x01 /* JBsastore = 86 */ ,
0x01 /* JBpop = 87 */ ,
0x01 /* JBpop2 = 88 */ ,
0x01 /* JBdup = 89 */ ,
0x01 /* JBdupx1 = 90 */ ,
0x01 /* JBdupx2 = 91 */ ,
0x01 /* JBdup2 = 92 */ ,
0x01 /* JBdup2x1 = 93 */ ,
0x01 /* JBdup2x2 = 94 */ ,
0x01 /* JBswap = 95 */ ,
0x01 /* JBiadd = 96 */ ,
0x01 /* JBladd = 97 */ ,
0x01 /* JBfadd = 98 */ ,
0x01 /* JBdadd = 99 */ ,
0x01 /* JBisub = 100 */ ,
0x01 /* JBlsub = 101 */ ,
0x01 /* JBfsub = 102 */ ,
0x01 /* JBdsub = 103 */ ,
0x01 /* JBimul = 104 */ ,
0x01 /* JBlmul = 105 */ ,
0x01 /* JBfmul = 106 */ ,
0x01 /* JBdmul = 107 */ ,
0x01 /* JBidiv = 108 */ ,
0x01 /* JBldiv = 109 */ ,
0x01 /* JBfdiv = 110 */ ,
0x01 /* JBddiv = 111 */ ,
0x01 /* JBirem = 112 */ ,
0x01 /* JBlrem = 113 */ ,
0x01 /* JBfrem = 114 */ ,
0x01 /* JBdrem = 115 */ ,
0x01 /* JBineg = 116 */ ,
0x01 /* JBlneg = 117 */ ,
0x01 /* JBfneg = 118 */ ,
0x01 /* JBdneg = 119 */ ,
0x01 /* JBishl = 120 */ ,
0x01 /* JBlshl = 121 */ ,
0x01 /* JBishr = 122 */ ,
0x01 /* JBlshr = 123 */ ,
0x01 /* JBiushr = 124 */ ,
0x01 /* JBlushr = 125 */ ,
0x01 /* JBiand = 126 */ ,
0x01 /* JBland = 127 */ ,
0x01 /* JBior = 128 */ ,
0x01 /* JBlor = 129 */ ,
0x01 /* JBixor = 130 */ ,
0x01 /* JBlxor = 131 */ ,
0x03 /* JBiinc = 132 */ ,
0x01 /* JBi2l = 133 */ ,
0x01 /* JBi2f = 134 */ ,
0x01 /* JBi2d = 135 */ ,
0x01 /* JBl2i = 136 */ ,
0x01 /* JBl2f = 137 */ ,
0x01 /* JBl2d = 138 */ ,
0x01 /* JBf2i = 139 */ ,
0x01 /* JBf2l = 140 */ ,
0x01 /* JBf2d = 141 */ ,
0x01 /* JBd2i = 142 */ ,
0x01 /* JBd2l = 143 */ ,
0x01 /* JBd2f = 144 */ ,
0x01 /* JBi2b = 145 */ ,
0x01 /* JBi2c = 146 */ ,
0x01 /* JBi2s = 147 */ ,
0x01 /* JBlcmp = 148 */ ,
0x01 /* JBfcmpl = 149 */ ,
0x01 /* JBfcmpg = 150 */ ,
0x01 /* JBdcmpl = 151 */ ,
0x01 /* JBdcmpg = 152 */ ,
0x0B /* JBifeq = 153 */ ,
0x0B /* JBifne = 154 */ ,
0x0B /* JBiflt = 155 */ ,
0x0B /* JBifge = 156 */ ,
0x0B /* JBifgt = 157 */ ,
0x0B /* JBifle = 158 */ ,
0x0B /* JBificmpeq = 159 */ ,
0x0B /* JBificmpne = 160 */ ,
0x0B /* JBificmplt = 161 */ ,
0x0B /* JBificmpge = 162 */ ,
0x0B /* JBificmpgt = 163 */ ,
0x0B /* JBificmple = 164 */ ,
0x0B /* JBifacmpeq = 165 */ ,
0x0B /* JBifacmpne = 166 */ ,
0x0B /* JBgoto = 167 */ ,
0x0B /* JBjsr = 168 */ ,
0x02 /* JBret = 169 */ ,
0x01 /* JBtableswitch = 170 */ ,
0x01 /* JBlookupswitch = 171 */ ,
0x01 /* JBireturn = 172 */ ,
0x01 /* JBlreturn = 173 */ ,
0x01 /* JBfreturn = 174 */ ,
0x01 /* JBdreturn = 175 */ ,
0x01 /* JBareturn = 176 */ ,
0x01 /* JBreturn = 177 */ ,
0x0B /* JBgetstatic = 178 */ ,
0x0B /* JBputstatic = 179 */ ,
0x0B /* JBgetfield = 180 */ ,
0x0B /* JBputfield = 181 */ ,
0x0B /* JBinvokevirtual = 182 */ ,
0x0B /* JBinvokespecial = 183 */ ,
0x0B /* JBinvokestatic = 184 */ ,
0x0D /* JBinvokeinterface = 185 */ ,
0x0D /* JBinvokedynamic = 186 */ ,
0x0B /* JBnew = 187 */ ,
0x02 /* JBnewarray = 188 */ ,
0x0B /* JBanewarray = 189 */ ,
0x01 /* JBarraylength = 190 */ ,
0x01 /* JBathrow = 191 */ ,
0x0B /* JBcheckcast = 192 */ ,
0x0B /* JBinstanceof = 193 */ ,
0x01 /* JBmonitorenter = 194 */ ,
0x01 /* JBmonitorexit = 195 */ ,
0x01 /* JBwide = 196 */ ,
0x0C /* JBmultianewarray = 197 */ ,
0x0B /* JBifnull = 198 */ ,
0x0B /* JBifnonnull = 199 */ ,
0x0D /* JBgotow = 200 */ ,
0x0D /* JBjsrw = 201 */ ,
0x01 /* JBbreakpoint = 202 */ ,
0x0B /* JBaconst_init = 203 */ ,
0x0B /* JBwithfield = 204 */ ,
0x01 /* JBunimplemented = 205 */ ,
0x01 /* JBunimplemented = 206 */ ,
0x01 /* JBunimplemented = 207 */ ,
0x01 /* JBunimplemented = 208 */ ,
0x01 /* JBunimplemented = 209 */ ,
0x01 /* JBunimplemented = 210 */ ,
0x01 /* JBunimplemented = 211 */ ,
0x01 /* JBunimplemented = 212 */ ,
0x01 /* JBunimplemented = 213 */ ,
0x01 /* JBunimplemented = 214 */ ,
0x01 /* JBunimplemented = 215 */ ,
0x01 /* JBunimplemented = 216 */ ,
0x01 /* JBunimplemented = 217 */ ,
0x01 /* JBunimplemented = 218 */ ,
0x01 /* JBunimplemented = 219 */ ,
0x01 /* JBunimplemented = 220 */ ,
0x01 /* JBunimplemented = 221 */ ,
0x01 /* JBunimplemented = 222 */ ,
0x01 /* JBunimplemented = 223 */ ,
0x01 /* JBunimplemented = 224 */ ,
0x01 /* JBunimplemented = 225 */ ,
0x01 /* JBunimplemented = 226 */ ,
0x01 /* JBunimplemented = 227 */ ,
0x01 /* JBunimplemented = 228 */ ,
0x01 /* JBunimplemented = 229 */ ,
0x01 /* JBunimplemented = 230 */ ,
0x01 /* JBunimplemented = 231 */ ,
0x01 /* JBunimplemented = 232 */ ,
0x01 /* JBunimplemented = 233 */ ,
0x01 /* JBunimplemented = 234 */ ,
0x01 /* JBunimplemented = 235 */ ,
0x01 /* JBunimplemented = 236 */ ,
0x01 /* JBunimplemented = 237 */ ,
0x01 /* JBunimplemented = 238 */ ,
0x01 /* JBunimplemented = 239 */ ,
0x01 /* JBunimplemented = 240 */ ,
0x01 /* JBunimplemented = 241 */ ,
0x01 /* JBunimplemented = 242 */ ,
0x01 /* JBunimplemented = 243 */ ,
0x01 /* JBunimplemented = 244 */ ,
0x01 /* JBunimplemented = 245 */ ,
0x01 /* JBunimplemented = 246 */ ,
0x01 /* JBunimplemented = 247 */ ,
0x01 /* JBunimplemented = 248 */ ,
0x01 /* JBunimplemented = 249 */ ,
0x01 /* JBunimplemented = 250 */ ,
0x01 /* JBunimplemented = 251 */ ,
0x01 /* JBunimplemented = 252 */ ,
0x01 /* JBunimplemented = 253 */ ,
0x01 /* JBimpdep1 = 254 */ ,
0x01 /* JBimpdep2 = 255 */
};
