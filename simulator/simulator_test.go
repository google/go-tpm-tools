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
	t.Helper()
	simulator, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}

func getEKModulus(t *testing.T, rwc io.ReadWriteCloser) *big.Int {
	t.Helper()
	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	return ek.PublicKey().(*rsa.PublicKey).N
}

func TestResetDoesntChangeEK(t *testing.T) {
	s := getSimulator(t)
	defer tpm2tools.CheckedClose(t, s)

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
	defer tpm2tools.CheckedClose(t, s)

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
	defer tpm2tools.CheckedClose(t, s)
	result, err := tpm2.GetRandom(s, 10)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	t.Log(result)
}

// The default EK modulus returned by the simulator when using a seed of 0.
func zeroSeedModulus() *big.Int {
	mod := new(big.Int)
	mod.SetString("26477589937104991909107546555596844814208501488398993637176547657040026510855262969599454342201099113570046958586074392392826189046589605606588308257325163261342553439301667460931252566414147127913702995490057967486186645056306958312086007589909165009386429083077296377200887146918939772513316195006666792119837801758230035524859461860350033253189094242924143497565958844676091714149214599630067691603355200610080948040721792826555203794339873010858621008154912642347482410965625629019620301070822787536053368781567603344040355963007625122652644931867174203344607909482751447522901014476802272093691307744409028025073", 10)
	return mod
}

func TestFixedSeedExpectedModulus(t *testing.T) {
	s, err := GetWithFixedSeedInsecure(0)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2tools.CheckedClose(t, s)

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
	defer tpm2tools.CheckedClose(t, s)

	modulus := getEKModulus(t, s)
	if modulus.Cmp(zeroSeedModulus()) == 0 {
		t.Fatalf("Moduli should not be equal when using different seeds")
	}
}
