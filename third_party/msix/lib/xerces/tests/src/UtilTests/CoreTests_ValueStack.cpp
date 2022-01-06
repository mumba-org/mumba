/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * $Id$
 */

// ---------------------------------------------------------------------------
//  XML4C2 includes
// ---------------------------------------------------------------------------
#include "CoreTests.hpp"
#include <xercesc/util/ValueStackOf.hpp>


// ---------------------------------------------------------------------------
//  Force a full instantiation of our stack and its enumerator, just to
//  insure that all methods get instantiated and compiled.
// ---------------------------------------------------------------------------
template ValueStackOf<int>;
template ValueStackEnumerator<int>;



// ---------------------------------------------------------------------------
//  Test entry point
// ---------------------------------------------------------------------------
static bool basicTests()
{
    ValueStackOf<double> testStack(500);

    return true;
}


// ---------------------------------------------------------------------------
//  Test entry point
// ---------------------------------------------------------------------------
bool testValueStack()
{
    XERCES_STD_QUALIFIER wcout  << L"----------------------------------\n"
                << L"Testing ValueStackOf template class\n"
                << L"----------------------------------" << XERCES_STD_QUALIFIER endl;

    bool retVal = true;

    try
    {
        // Call other local methods to do specific tests
        XERCES_STD_QUALIFIER wcout << L"Testing ValueStackOf basics" << XERCES_STD_QUALIFIER endl;
        if (!basicTests())
        {
            XERCES_STD_QUALIFIER wcout << L"ValueStackOf basic tests failed" << XERCES_STD_QUALIFIER endl;
            retVal = false;
        }
         else
        {
            XERCES_STD_QUALIFIER wcout  << L"ValueArrayOf constructor tests passed"
                        << XERCES_STD_QUALIFIER endl;
        }
        XERCES_STD_QUALIFIER wcout << XERCES_STD_QUALIFIER endl;
    }

    catch(const XMLException& toCatch)
    {
        XERCES_STD_QUALIFIER wcout  << L"  ERROR: Unexpected exception!\n   Msg: "
                    << toCatch.getMessage() << XERCES_STD_QUALIFIER endl;
        return false;
    }
    return retVal;
}
