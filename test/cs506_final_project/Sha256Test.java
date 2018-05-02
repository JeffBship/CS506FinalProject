/**
 * Test package is modified for CCSU CS506 project
 * to include input space and graph coverage in combined test cases.
 * @author Jeff Blankenship
 * @author Austin Barret
 * 
 */


// <editor-fold defaultstate="collapsed" desc=" DESCRIPTION ">
/** ****************************************************************************
 * NTRU Cryptography Reference Source Code
 *
 * Copyright (C) 2009-2016  Security Innovation (SI)
 *
 * SI has dedicated the work to the public domain by waiving all of its rights
 * to the work worldwide under copyright law, including all related and
 * neighboring rights, to the extent allowed by law.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * You can copy, modify, distribute and perform the work, even for commercial
 * purposes, all without asking permission. You should have received a copy of
 * the creative commons license (CC0 1.0 universal) along with this program.
 * See the license file for more information.
 *
 *
 ******************************************************************************** */

/*
  * Contents: Tests for the SHA256 class.
  *
  * This just tests the correctness of the SHA algorithm by comparing
  * its output to known test vectors. The test vectors come from the
  * cryptolib library and are a combination of the FIPS 180-2 test
  * vectors and home-grown test vectors.
 */
// </editor-fold>
package cs506_final_project;


import cs506_final_project.Sha256;
import org.junit.Test;
import static org.junit.Assert.*;

/////////////////////////////////////////////////////////////////////////
// Tests:
// THESE ARE THE ORIGINAL TESTS
//   - update
//       - null buffer
//       - negative offset
//       - negative length
//       - offset+length overrun buffer end
//       - calling multiple times on split buffers is the same as calling
//         once on full buffer.
//
//   - known-value tests. These are positive tests for update and finishDigest.

public class Sha256Test {
  
    //Input Space case C1C2C3C4=TFFT
    //path coverage: 1 2 3!
    @Test(expected=NullPointerException.class)
    public void testTFFF123()
    {
        Sha256 s = new Sha256();
        s.update(sNull, 0, 0);
    }
    
    //Input Space case C1C2C3C4=FTFF
    //path coverage: 1 2 4 5!
    @Test(expected=IllegalArgumentException.class)
    public void testFTFF1245()
    {
        Sha256 s = new Sha256();
        s.update(sEmpty, 1, 1);
    }
    
    //Input Space case C1C2C3C4=FFTF
    //path coverage: 1 2 4 6 7!
    @Test(expected=IllegalArgumentException.class)
    public void testFFTF12467()
    {
        Sha256 s = new Sha256();
        s.update(sEmpty, -1, 0);
    }
    
    //Input Space case C1C2C3C4=FFFT
    //path coverage: 1 2 4 6 8 9!
    @Test(expected=IllegalArgumentException.class)
    public void testFFFT124689()
    {
        Sha256 s = new Sha256();
        s.update(sEmpty, 0, -1);
    }
    
    //Input Space case C1C2C3C4=FFFF   (BASE CASE)
    //path coverage: full path, without entering while loop
    //1 2 4 6 8 10 12!
    @Test
    public void testPathNoLoop()
    {
        Sha256 s = new Sha256();
        s.update(s64, 0, 64);
    }
    
    //path coverage: full path with two cycles of while loop
    //1 2 4 6 8 10 11 10 11 10 12!
    @Test
    public void testPathLoopTwice()
    {
        Sha256 s = new Sha256();
        s.update(s64, 0, 64);
    }
    
    
    

    static final byte sNull[] = null;
    static final byte sEmpty[] = {};

    static final byte s64[] = {
        (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
        (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65,
        (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66,
        (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x6f, (byte)0x70, (byte)0x71, (byte)0x72,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73
    };
    
    static final byte s130[] = {
        (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
        (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65,
        (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66,
        (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x6f, (byte)0x70, (byte)0x71, (byte)0x72,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x61, (byte)0x62, (byte)0x63, (byte)0x64,
        (byte)0x62, (byte)0x63, (byte)0x64, (byte)0x65,
        (byte)0x63, (byte)0x64, (byte)0x65, (byte)0x66,
        (byte)0x64, (byte)0x65, (byte)0x66, (byte)0x67,
        (byte)0x65, (byte)0x66, (byte)0x67, (byte)0x68,
        (byte)0x66, (byte)0x67, (byte)0x68, (byte)0x69,
        (byte)0x67, (byte)0x68, (byte)0x69, (byte)0x6a,
        (byte)0x68, (byte)0x69, (byte)0x6a, (byte)0x6b,
        (byte)0x69, (byte)0x6a, (byte)0x6b, (byte)0x6c,
        (byte)0x6a, (byte)0x6b, (byte)0x6c, (byte)0x6d,
        (byte)0x6b, (byte)0x6c, (byte)0x6d, (byte)0x6e,
        (byte)0x6c, (byte)0x6d, (byte)0x6e, (byte)0x6f,
        (byte)0x6d, (byte)0x6e, (byte)0x6f, (byte)0x70,
        (byte)0x6e, (byte)0x6f, (byte)0x70, (byte)0x71,
        (byte)0x6f, (byte)0x70, (byte)0x71, (byte)0x72,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x72, (byte)0x73
    };
    
    
}
