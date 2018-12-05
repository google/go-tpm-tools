/********************************************************************************/
/*										*/
/*		Instance data for the Platform module. 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: PlatformData.h 1311 2018-08-23 21:39:29Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2018.				*/
/*										*/
/********************************************************************************/

/* A.1 PlatformData.h */
/* This file contains the instance data for the Platform module. It is collected in this file so
   that the state of the module is easier to manage. */
#ifndef _PLATFORM_DATA_H_
#define _PLATFORM_DATA_H_
#include      "Implementation.h"
/* From Cancel.c Cancel flag.  It is initialized as FALSE, which indicate the command is not being
   canceled */
extern int     s_isCanceled;

#ifdef _MSC_VER
#include <sys/types.h>
#include <sys/timeb.h>
#else
#include <sys/time.h>
#include <time.h>
#endif

#ifndef HARDWARE_CLOCK
typedef uint64_t     clock64_t;
// This is the value returned the last time that the system clock was read. This is only relevant
// for a simulator or virtual TPM.
extern clock64_t       s_realTimePrevious;
// These values are used to try to synthesize a long lived version of clock().
extern clock64_t        s_lastSystemTime;
extern clock64_t        s_lastReportedTime;
// This is the rate adjusted value that is the equivalent of what would be read from a hardware
// register that produced rate adjusted time.
extern clock64_t        s_tpmTime;
#endif // HARDWARE_CLOCK

/* This value indicates that the timer was reset */
extern BOOL              s_timerReset;
/* This value indicates that the timer was stopped. It causes a clock discontinuity. */
extern BOOL              s_timerStopped;
/* CLOCK_NOMINAL is the number of hardware ticks per mS. A value of 300000 means that the nominal
   clock rate used to drive the hardware clock is 30 MHz(). The adjustment rates are used to
   determine the conversion of the hardware ticks to internal hardware clock value. In practice, we
   would expect that there would be a hardware register will accumulated mS. It would be incremented
   by the output of a pre-scaler. The pre-scaler would divide the ticks from the clock by some value
   that would compensate for the difference between clock time and real time. The code in Clock does
   the emulation of this function.*/ 
#define     CLOCK_NOMINAL           30000
/* A 1% change in rate is 300 counts */
#define     CLOCK_ADJUST_COARSE     300
/* A 0.1% change in rate is 30 counts */
#define     CLOCK_ADJUST_MEDIUM     30
/* A minimum change in rate is 1 count */
#define     CLOCK_ADJUST_FINE       1
/* The clock tolerance is +/-15% (4500 counts) Allow some guard band (16.7%) */
#define     CLOCK_ADJUST_LIMIT      5000
/* This variable records the time when _plat__TimerReset() is called.  This mechanism allow us to
   subtract the time when TPM is power off from the total time reported by clock() function */
extern uint64_t        s_initClock;
/* This variable records the timer adjustment factor. */
extern unsigned int         s_adjustRate;
/* From LocalityPlat.c Locality of current command */
extern unsigned char s_locality;
/* From NVMem.c Choose if the NV memory should be backed by RAM or by file. If this macro is
   defined, then a file is used as NV.  If it is not defined, then RAM is used to back NV
   memory. Comment out to use RAM. */
#if (!defined VTPM) || ((VTPM != NO) && (VTPM != YES))
#   undef VTPM
#   define      VTPM            YES                 // Default: Either YES or NO
#endif

// For a simulation, use a file to back up the NV

#if (!defined FILE_BACKED_NV) || ((FILE_BACKED_NV != NO) && (FILE_BACKED_NV != YES))
#   undef   FILE_BACKED_NV
#   define  FILE_BACKED_NV          (VTPM && YES)     // Default: Either YES or NO
#endif
#if 0	/* kgold Don't want SIMULATION for a VTPM */
#if !SIMULATION
#   undef       FILE_BACKED_NV
#   define      FILE_BACKED_NV          NO
#endif // SIMULATION
#endif

extern unsigned char     s_NV[NV_MEMORY_SIZE];
extern BOOL              s_NvIsAvailable;
extern BOOL              s_NV_unrecoverable;
extern BOOL              s_NV_recoverable;
/* From PPPlat.c Physical presence.  It is initialized to FALSE */
extern BOOL     s_physicalPresence;
/* From Power */
extern BOOL        s_powerLost;
/* From Entropy.c */
extern uint32_t        lastEntropy;
#endif // _PLATFORM_DATA_H_
