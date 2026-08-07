/*
 * Copyright 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package simulator

import (
	"crypto/rsa"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

func getSimulator(t *testing.T) *Simulator {
	t.Helper()
	simulator, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}

func getEKModulus(t *testing.T, rwc io.ReadWriteCloser) *big.Int {
	t.Helper()
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	return ek.PublicKey().(*rsa.PublicKey).N
}

func TestResetDoesntChangeEK(t *testing.T) {
	s := getSimulator(t)
	defer client.CheckedClose(t, s)

	modulus1 := getEKModulus(t, s)
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	modulus2 := getEKModulus(t, s)

	if modulus1.Cmp(modulus2) != 0 {
		t.Fatal("Reset() should not change the EK")
	}
}
func TestManufactureResetChangesEK(t *testing.T) {
	s := getSimulator(t)
	defer client.CheckedClose(t, s)

	modulus1 := getEKModulus(t, s)
	if err := s.ManufactureReset(); err != nil {
		t.Fatal(err)
	}
	modulus2 := getEKModulus(t, s)

	if modulus1.Cmp(modulus2) == 0 {
		t.Fatal("ManufactureReset() should change the EK")
	}
}

func TestGetRandom(t *testing.T) {
	s := getSimulator(t)
	defer client.CheckedClose(t, s)
	result, err := tpm2.GetRandom(s, 10)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	t.Log(result)
}

// The default EK modulus returned by the simulator when using a seed of 0.
func zeroSeedModulus() *big.Int {
	mod := new(big.Int)
	mod.SetString("20290863024442403286288144545437770451179836972830597848952875033203140987942623367439092111444082453908928460791539277393240180945003815547636734772226814630607516888326258379705600580546138777547764911582217253535915959312177307966597246982516335345002963203446587829427891185172320207351030361528817804843023828255249842854581196706278516400138261050551534885755677121979450248671113486186803375680867998127864456239621338755160916987218736955463282264121801316155973237783893658236376251680981312934136626838055219286741966002217404853664927036506040424984958038241091975937891483959347832209054595769870867540351", 10)
	return mod
}

func TestFixedSeedExpectedModulus(t *testing.T) {
	s, err := GetWithFixedSeedInsecure(0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CheckedClose(t, s)

	modulus := getEKModulus(t, s)
	if modulus.Cmp(zeroSeedModulus()) != 0 {
		t.Fatalf("getEKModulus() = %v, want %v", modulus, zeroSeedModulus())
	}
}

func TestDifferentSeedDifferentModulus(t *testing.T) {
	s, err := GetWithFixedSeedInsecure(1)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CheckedClose(t, s)

	modulus := getEKModulus(t, s)
	if modulus.Cmp(zeroSeedModulus()) == 0 {
		t.Fatalf("Moduli should not be equal when using different seeds")
	}
}
