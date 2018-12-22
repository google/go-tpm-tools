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

func TestFixedSeed(t *testing.T) {
	s, err := GetWithFixedSeed(5)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	modulus := getEKModulus(t, s)
	modulusExpected := big.NewInt(0)
	modulusExpected.SetString("22976074755822222306012918638589617991468007801607618594786013809405844817261489096106158605146104065255544111331281321230621832812370678063780391433334909008830270005840271537008835533054955331514047864955658355650189653402871231036589014204021350613788044928872736134330575528746204441539102822205823474443854298256203823266416501461214851929261468242157634609844006231572719846970510199948667774979118308704085474690417911809116188817976400529052998193467692499527731070520278656144903200661933612078540717644348566755893975426760754336539004606893945772071800176301822966566038773218417062655479178720801478584829", 10)
	if modulus.Cmp(modulusExpected) != 0 {
		t.Fatalf("Got %v expected %v", modulus, modulusExpected)
	}
}
