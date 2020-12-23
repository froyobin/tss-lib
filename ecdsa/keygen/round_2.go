// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	// 6. verify dln proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.kgRound1Messages)*2)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		H1j, H2j, NTildej :=
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde()
		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
		}
		if _, found := h1H2Map[h2JHex]; found {
			return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
		}
		h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}
		wg.Add(2)
		go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof1, err := r1msg.UnmarshalDLNProof1(); err != nil || !dlnProof1.Verify(H1j, H2j, NTildej) {
				dlnProof1FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)
		go func(j int, msg tss.ParsedMessage, r1msg *KGRound1Message, H1j, H2j, NTildej *big.Int) {
			if dlnProof2, err := r1msg.UnmarshalDLNProof2(); err != nil || !dlnProof2.Verify(H2j, H1j, NTildej) {
				dlnProof2FailCulprits[j] = msg.GetFrom()
			}
			wg.Done()
		}(j, msg, r1msg, H1j, H2j, NTildej)
	}
	wg.Wait()
	for _, culprit := range append(dlnProof1FailCulprits, dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j, ...
	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KGRound1Message)
		paillierPK, H1j, H2j, NTildej, KGC :=
			r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalCommitment()
		round.save.PaillierPKs[j] = paillierPK // used in round 4
		round.save.NTildej[j] = NTildej
		round.save.H1j[j], round.save.H2j[j] = H1j, H2j
		round.temp.KGCs[j] = KGC
	}

	// 5. p2p send share ij to Pj
	shares := round.temp.shares
	round.temp.encryptedShares = make([]paillier.EncryptedMsg, len(round.Parties().IDs()))

	for j, Pj := range round.Parties().IDs() {
		e, r, err := round.save.PaillierPKs[j].EncryptAndReturnRandomness(shares[j].Share)
		if err != nil {
			return round.WrapError(err, nil)
		}
		encryptedValue := paillier.EncryptedMsg{
			EncryptedData: e,
			RandomR:       r,
		}
		round.temp.encryptedShares[Pj.Index] = encryptedValue
	}
	round.temp.broadcastEncryptedShare = make([][]byte, len(round.temp.encryptedShares))
	for i, el := range round.temp.encryptedShares {
		round.temp.broadcastEncryptedShare[i] = el.EncryptedData.Bytes()
	}

	// 7. BROADCAST de-commitments of Shamir poly*G
	r2msg := NewKGRound2Message(round.PartyID(), round.temp.deCommitPolyG, round.temp.broadcastEncryptedShare)
	round.temp.kgRound2Messages[round.PartyID().Index] = r2msg
	round.out <- r2msg

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}

	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round, false}
}
