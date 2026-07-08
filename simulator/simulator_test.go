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
	mod.SetString("22714460010425758006264227951301675104742012402952111656614687887301265413183186627897176866762321787968945110356821705892077098155833859109082998444113040319145605009776843398011990885704509756856248203522629864283381889816538800899736287448956761736002383055062540717577741117685144622471779829642874315434137307417149666866735428495153374905784197995881229661971147634909410159951675057231118639985978621838592078586409696126104497547801403023613210004812344624790397708278727668829657123854721636610243565461580295707066440401383362326885370497411229478799014360414836832832352605407076063697273440989196325067449", 10)
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
