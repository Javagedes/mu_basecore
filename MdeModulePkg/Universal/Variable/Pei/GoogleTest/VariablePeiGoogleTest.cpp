/** @file
  Tests for Variable/Pei/Variable.c.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <gtest/gtest.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/DebugLib.h>
  #include <Library/PcdLib.h>
  #include "../Variable.h"
  //#include "../Variable.c"
}

////////////////////////////////////////////////////////////////////////
// Variable Tests
////////////////////////////////////////////////////////////////////////

class VariableTest : public ::testing::Test {
protected:
  // Add any setup code if needed
  virtual void
  SetUp (
    )
  {
    // Initialize any resources or variables
  }

  // Add any cleanup code if needed
  virtual void
  TearDown (
    )
  {
    // Clean up any resources or variables
  }
};

// Test Description
// Test to make sure I can build and run tests
TEST_F (VariableTest, TestForTest) {
  PeiGetNextVariableName(NULL, NULL, NULL, NULL);
  EXPECT_FALSE (false);
}

////////////////////////////////////////////////////////////////////////////////
// Run the tests
////////////////////////////////////////////////////////////////////////////////
int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}