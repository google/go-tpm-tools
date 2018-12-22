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

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

func getSimulator(t *testing.T) *Simulator {
	simulator, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}

func getEKModulus(t *testing.T, rwc io.ReadWriteCloser) *big.Int {
	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	return ek.PublicKey().(*rsa.PublicKey).N
}

func TestResetDoesntChangeEK(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()

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
	defer s.Close()

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
	defer s.Close()
	result, err := tpm2.GetRandom(s, 10)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	t.Log(result)
}
