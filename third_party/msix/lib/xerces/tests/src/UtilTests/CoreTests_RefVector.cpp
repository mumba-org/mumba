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
//  XML4C2 Includes
// ---------------------------------------------------------------------------
#include "CoreTests.hpp"
#include <xercesc/util/RefVectorOf.hpp>
#include <xercesc/util/ArrayIndexOutOfBoundsException.hpp>



// ---------------------------------------------------------------------------
//  Force a full instantiation of the vector and its enumerator just to insure
//  that all methods get instantiated and compiled.
// ---------------------------------------------------------------------------
template RefVectorOf<int>;
template RefVectorEnumerator<int>;



// ---------------------------------------------------------------------------
//  Templatized testing code. These allow the exact same tests to be run
//  for any number of instantiation types over the by value vectors.
// ---------------------------------------------------------------------------
template <class T> bool commonRefTests()
{
    const unsigned int  testMax = 3;
    bool                caughtIt;

    //
    //  Create a vector of testMax of the instantiation type. Tell it that
    //  we adopt elements.
    //
    RefVectorOf<T> testVec(testMax, true);

    // Make sure the initial capacity is what we set
    if (testVec.curCapacity() != testMax)
    {
        XERCES_STD_QUALIFIER wcout << L"   Init capacity was incorrect" << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Make sure the initial size is zero
    if (testVec.size() != 0)
    {
        XERCES_STD_QUALIFIER wcout << L"   Init size was not correct" << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Add a value and check the count is 1
    testVec.addElement(new T);
    if (testVec.size() != 1)
    {
        XERCES_STD_QUALIFIER wcout << L"   Adding one element caused bad size" << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Add another value and check the count is 2
    testVec.addElement(new T);
    if (testVec.size() != 2)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Adding another element caused bad size"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Add two more, which should cause an expansion of the vector
    testVec.addElement(new T);
    testVec.addElement(new T);

    if (testVec.curCapacity() == testMax)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Adding another element failed to cause an expansion"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Check that we get an array bounds exception after an expansion
    caughtIt = false;
    try
    {
        testVec.elementAt(4);
    }

    catch(const ArrayIndexOutOfBoundsException&)
    {
        caughtIt = true;
    }

    if (!caughtIt)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Failed to catch array bounds error at element 4"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Remove an item and see if the count went down by one
    testVec.removeElementAt(0);

    if (testVec.size() != 3)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Removing an element did not adjust size correctly"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Remove the rest of them and make sure we hit zero
    testVec.removeElementAt(0);
    testVec.removeElementAt(0);
    testVec.removeElementAt(0);

    if (testVec.size() != 0)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Removing all elements did not zero the size"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Check that we get an array bounds exception now still
    caughtIt = false;
    try
    {
        testVec.elementAt(0);
    }

    catch(const ArrayIndexOutOfBoundsException&)
    {
        caughtIt = true;
    }

    if (!caughtIt)
    {
        XERCES_STD_QUALIFIER wcout  << L"   Failed to catch array bounds error at element 0"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Add a few more elements back in, via insertion
    testVec.insertElementAt(new T, 0);
    testVec.insertElementAt(new T, 0);
    testVec.insertElementAt(new T, 0);
    if (testVec.size() != 3)
    {
        XERCES_STD_QUALIFIER wcout << L"   Inserting elements caused bad size" << XERCES_STD_QUALIFIER endl;
        return false;
    }

    // Now do a remove all elements
    testVec.removeAllElements();

    if (testVec.size() != 0)
    {
        XERCES_STD_QUALIFIER wcout  << L"   removeAllElements caused bad size" << XERCES_STD_QUALIFIER endl;
        return false;
    }

    return true;
}


template <class T> bool extendedRefTests()
{
    const unsigned int testMax = 8;

    // Create a test vector and put in ascending test values
    RefVectorOf<T> testVec(testMax, true);
    testVec.addElement(new T(0));
    testVec.addElement(new T(1));
    testVec.addElement(new T(2));
    testVec.addElement(new T(3));
    testVec.addElement(new T(4));
    testVec.addElement(new T(5));
    testVec.addElement(new T(6));
    testVec.addElement(new T(7));

    // Now check that they went in that way
    unsigned int index;
    for (index = 0; index < testMax; index++)
    {
        if (*testVec.elementAt(index) != T(index))
        {
            XERCES_STD_QUALIFIER wcout  << L"   addElement put elements in wrong order"
                        << XERCES_STD_QUALIFIER endl;
            return false;
        }
    }

    // Remove the zero'th element and test again
    testVec.removeElementAt(0);

    for (index = 0; index < testMax-1; index++)
    {
        if (*testVec.elementAt(index) != T(index+1))
        {
            XERCES_STD_QUALIFIER wcout  << L"   removeElement at head removed wrong element"
                        << XERCES_STD_QUALIFIER endl;
            return false;
        }
    }

    // Test edge case by removing last element and test again
    testVec.removeElementAt(6);

    for (index = 0; index < testMax-2; index++)
    {
        if (*testVec.elementAt(index) != T(index+1))
        {
            XERCES_STD_QUALIFIER wcout  << L"   removeElement at end removed wrong element"
                        << XERCES_STD_QUALIFIER endl;
            return false;
        }
    }
    return true;
}



// ---------------------------------------------------------------------------
//  Local functions
// ---------------------------------------------------------------------------
static bool doBasicTests()
{
    bool retVal = true;

    //
    // Do the common reference vector tests for ints, bools and strings.
    //
    XERCES_STD_QUALIFIER wcout << L"Testing RefVectorOf<int>, common tests" << XERCES_STD_QUALIFIER endl;
    if (!commonRefTests<int>())
    {
        XERCES_STD_QUALIFIER wcout << L"RefVectorOf<int> failed" << XERCES_STD_QUALIFIER endl;
        retVal = false;
    }
     else
    {
        XERCES_STD_QUALIFIER wcout << L"RefVectorOf<int> passed" << XERCES_STD_QUALIFIER endl;
    }
    XERCES_STD_QUALIFIER wcout << XERCES_STD_QUALIFIER endl;

    XERCES_STD_QUALIFIER wcout << L"Testing RefVectorOf<bool>, common tests" << XERCES_STD_QUALIFIER endl;
    if (!commonRefTests<bool>())
    {
        XERCES_STD_QUALIFIER wcout << L"RefVectorOf<bool> failed" << XERCES_STD_QUALIFIER endl;
        retVal = false;
    }
     else
    {
        XERCES_STD_QUALIFIER wcout << L"RefVectorOf<bool> passed" << XERCES_STD_QUALIFIER endl;
    }
    XERCES_STD_QUALIFIER wcout << XERCES_STD_QUALIFIER endl;


    //
    //  And now do the second round of extended tests. These require that
    //  the instantiation type be of a fundamental value, because its going
    //  to test element ordering issues.
    //
    XERCES_STD_QUALIFIER wcout << L"Testing RefVectorOf<int>, extended tests" << XERCES_STD_QUALIFIER endl;
    if (!extendedRefTests<int>())
    {
        XERCES_STD_QUALIFIER wcout << L"Extended RefVectorOf<int> failed" << XERCES_STD_QUALIFIER endl;
        retVal = false;
    }
     else
    {
        XERCES_STD_QUALIFIER wcout << L"Extended RefVectorOf<int> passed" << XERCES_STD_QUALIFIER endl;
    }
    XERCES_STD_QUALIFIER wcout << XERCES_STD_QUALIFIER endl;

    return retVal;
}


static bool enumTests()
{
    // Create a vector and fill it in with some known values
    RefVectorOf<unsigned int> testVec(32, true);

    unsigned int index;
    for (index = 0; index < 32; index++)
        testVec.addElement(new unsigned int(index));

    // Create an enumeration for it
    RefVectorEnumerator<unsigned int> enumTest(&testVec);
    index = 0;
    while (enumTest.hasMoreElements())
    {
        if (enumTest.nextElement() != index++)
        {
            XERCES_STD_QUALIFIER wcout << L"    Enumerator sequence was incorrect" << XERCES_STD_QUALIFIER endl;
            return false;
        }
    }

    if (index != 32)
    {
        XERCES_STD_QUALIFIER wcout  << L"    Enumerator did not enum enough elements"
                    << XERCES_STD_QUALIFIER endl;
        return false;
    }
    return true;
}



// ---------------------------------------------------------------------------
//  Test entry point
// ---------------------------------------------------------------------------
bool testRefVector()
{
    XERCES_STD_QUALIFIER wcout  << L"----------------------------------\n"
                << L"Testing RefVectorOf template class\n"
                << L"----------------------------------" << XERCES_STD_QUALIFIER endl;

    bool retVal = true;

    try
    {
        // Do the basic suite of tests
        if (!doBasicTests())
            retVal = false;

        // Test the enumerator
        XERCES_STD_QUALIFIER wcout << L"Testing RefVectorEnumerator" << XERCES_STD_QUALIFIER endl;
        if (!enumTests())
        {
            XERCES_STD_QUALIFIER wcout << L"RefVectorEnumeration failed" << XERCES_STD_QUALIFIER endl;
            retVal = false;
        }
         else
        {
            XERCES_STD_QUALIFIER wcout << L"RefVectorEnumeration passed" << XERCES_STD_QUALIFIER endl;
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
