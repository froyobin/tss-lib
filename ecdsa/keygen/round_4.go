// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	"sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) findCulprits(j int, abortItems []*KGRound3Message_AbortDataEntry) []int {
	var culprintsIndex []int
	reporterPubKey := round.save.PaillierPKs[j]
	for _, el := range abortItems {
		shareOwnerValue := round.temp.recvEncryptedShares[el.Index]
		// if share is nil,we need to verify whether the share own send an invalid share
		if el.ShareX == nil || el.ShareM == nil {
			NSq := reporterPubKey.NSquare()
			c := new(big.Int).SetBytes(shareOwnerValue[j])
			if c.Cmp(zero) == -1 || c.Cmp(NSq) != -1 { // c < 0 || c >= N2 ?
				culprintsIndex = append(culprintsIndex, int(el.Index))
				continue
			} else {
				culprintsIndex = append(culprintsIndex, j)
				continue
			}
		}
		m := new(big.Int).SetBytes(el.ShareM)
		r := new(big.Int).SetBytes(el.ShareX)
		// the reported value from the "victim"
		reportedValue, _, err := reporterPubKey.EncryptWithChosenRandomness(m, r)
		if err != nil {
			culprintsIndex = append(culprintsIndex, j)
			continue
		}
		// this indicate the share owner is the malicious node
		if reportedValue.Cmp(new(big.Int).SetBytes(shareOwnerValue[j])) == 0 {
			culprintsIndex = append(culprintsIndex, int(el.Index))
			continue
		} else {
			culprintsIndex = append(culprintsIndex, j)
			continue
		}
	}
	// this indicate the one who claim the incorrect VSS should be blamed.
	if len(culprintsIndex) == 0 {
		culprintsIndex = append(culprintsIndex, j)
	}
	return culprintsIndex
}

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()
	r3msgs := round.temp.kgRound3Messages
	identyfyAbort := false
	chs := make([]chan bool, len(r3msgs))
	// r4 messages are assumed to be available and != nil in this function
	for i := range chs {
		chs[i] = make(chan bool)
	}
	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()
	ecdsaPub := round.save.ECDSAPub
	var identifyingAbortCulprits []*tss.PartyID
	var identifyingAbortCulpritsLock sync.Mutex
	if round.vssAbort {
		identyfyAbort = true
		identifyingAbortCulpritsLock.Lock()
		for _, el := range round.temp.vssAbortData.Item {
			identifyingAbortCulprits = append(identifyingAbortCulprits, Ps[el.Index])
		}
		identifyingAbortCulpritsLock.Unlock()
	}

	// 1-3. (concurrent)
	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}
		r3msg := msg.Content().(*KGRound3Message)
		go func(r3msg *KGRound3Message, j int, ch chan<- bool) {
			switch c := r3msg.GetContent().(type) {
			case *KGRound3Message_Abort:
				identyfyAbort = true
				culpritIndex := round.findCulprits(j, c.Abort.GetItem())
				identifyingAbortCulpritsLock.Lock()
				for _, el := range culpritIndex {
					identifyingAbortCulprits = append(identifyingAbortCulprits, Ps[el])
				}
				identifyingAbortCulpritsLock.Unlock()
				ch <- false

			case *KGRound3Message_Success:
				if !round.vssAbort {
					ppk := round.save.PaillierPKs[j]
					prf := r3msg.UnmarshalProofInts()
					ok, err := prf.Verify(ppk.N, PIDs[j], ecdsaPub)
					if err != nil {
						common.Logger.Error(round.WrapError(err, Ps[j]).Error())
						ch <- false
						return
						return
					}
					ch <- ok
					return
				}
				ch <- true
			default:
				common.Logger.Error(round.WrapError(errors.New("unknown message type"), Ps[j]).Error())
				ch <- false

			}
		}(r3msg, j, chs[j])

	}

	// consume unbuffered channels (end the goroutines)
	for j, ch := range chs {
		if j == i {
			round.ok[j] = true
			continue
		}
		round.ok[j] = <-ch
	}
	// if we have any identifying abort message, we enter identifying abort and will not continue the tss.
	if identyfyAbort {
		common.Logger.Errorf("vss verify faild with culprits %v", identifyingAbortCulprits)
		return round.WrapError(errors.New("vss verify failed"), identifyingAbortCulprits...)
	}
	culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
	for j, ok := range round.ok {
		if !ok {
			culprits = append(culprits, Ps[j])
			common.Logger.Warningf("paillier verify failed for party %s", Ps[j])
			continue
		}
		common.Logger.Debugf("paillier verify passed for party %s", Ps[j])

	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("paillier verify failed"), culprits...)
	}

	round.end <- *round.save

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
