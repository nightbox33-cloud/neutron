package keeper_test

// Audit PoC v3: value-conservation fuzz for the production DEX (x/dex @ neutron v11 HEAD 9195772b).
//
// Every state-changing message runs in its own cache context and is committed only
// if the handler returns nil, reproducing real DeliverTx atomicity (the apptesting
// suite has no tx wrapper, so a handler error would otherwise leave partially
// applied state behind -- that artifact produced the false "leak" in v1/v2).
//
// Hard invariants:
//  1. after every action, for each denom, the chain-wide sum of all balances is
//     constant (no value created or destroyed) and equals that denom's bank supply.
//  2. at quiescence every actor can fully exit: all LP shares withdrawable and all
//     limit-order claims payable.
//  3. after the full exit, at most one whole token per accounting object (pool,
//     active/inactive tranche, tranche-user record) may still sit in the module
//     account on top of users' fractional credits -- anything larger is stranded
//     third-party value.

import (
	"fmt"
	"math/rand" //nolint:gosec // deterministic fuzz driver for invariants
	"strings"
	"testing"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/neutron-org/neutron/v11/testutil/apptesting"
	testutils "github.com/neutron-org/neutron/v11/x/dex/keeper/internal/testutils"
	dexkeeper "github.com/neutron-org/neutron/v11/x/dex/keeper"
	"github.com/neutron-org/neutron/v11/x/dex/types"
	mathutils "github.com/neutron-org/neutron/v11/utils/math"
)

type ConservationSuite struct {
	apptesting.KeeperTestHelper
	ms          types.MsgServer
	actors      []sdk.AccAddress
	startSupply map[string]math.Int
	rng         *rand.Rand
}

func TestDEXValueConservationFuzz(t *testing.T) {
	suite.Run(t, new(ConservationSuite))
}

func (s *ConservationSuite) SetupTest() {
	s.Setup()
	s.ms = dexkeeper.NewMsgServerImpl(s.App.DexKeeper)
	s.rng = rand.New(rand.NewSource(1337)) //nolint:gosec
	s.actors = nil
	for i := 0; i < 8; i++ {
		addr := s.SetupAddr(i)
		s.actors = append(s.actors, addr)
		testutils.FundAccount(s.App.BankKeeper, s.Ctx, addr, sdk.NewCoins(
			testutils.NewACoin(math.NewInt(1_000_000_000_000)),
			testutils.NewBCoin(math.NewInt(1_000_000_000_000)),
		))
	}
	s.startSupply = map[string]math.Int{
		"TokenA": s.chainTotal("TokenA"),
		"TokenB": s.chainTotal("TokenB"),
	}
	for _, denom := range []string{"TokenA", "TokenB"} {
		require.Equal(s.T(), s.App.BankKeeper.GetSupply(s.Ctx, denom).Amount.String(),
			s.chainTotal(denom).String(), "%s bank inconsistent right after funding", denom)
	}
}

// ---------------------------------------------------------------- infrastructure

// runTx emulates one DeliverTx: state is kept only if the handler returns nil.
func (s *ConservationSuite) runTx(f func() error) bool {
	cacheCtx, write := s.Ctx.CacheContext()
	parent := s.Ctx
	s.Ctx = cacheCtx
	err := f()
	s.Ctx = parent
	if err != nil {
		return false
	}
	write()
	return true
}

func (s *ConservationSuite) modAddr() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.ModuleName)
}

func (s *ConservationSuite) supply(denom string, addr sdk.AccAddress) math.Int {
	return s.App.BankKeeper.GetBalance(s.Ctx, addr, denom).Amount
}

func (s *ConservationSuite) modSupply(denom string) math.Int {
	return s.supply(denom, s.modAddr())
}

func (s *ConservationSuite) holders(denom string) map[string]math.Int {
	out := make(map[string]math.Int)
	s.App.BankKeeper.IterateAllBalances(s.Ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
		if coin.Denom == denom && !coin.Amount.IsZero() {
			out[addr.String()] = coin.Amount
		}
		return false
	})
	return out
}

// chainTotal sums every balance in the bank for a denom.
func (s *ConservationSuite) chainTotal(denom string) math.Int {
	total := math.ZeroInt()
	s.App.BankKeeper.IterateAllBalances(s.Ctx, func(_ sdk.AccAddress, coin sdk.Coin) bool {
		if coin.Denom == denom {
			total = total.Add(coin.Amount)
		}
		return false
	})
	return total
}

// allBalances snapshots every (address, denom) balance in the whole bank.
func (s *ConservationSuite) allBalances() map[string]math.Int {
	out := make(map[string]math.Int)
	s.App.BankKeeper.IterateAllBalances(s.Ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
		out[fmt.Sprintf("%s|%s", addr.String(), coin.Denom)] = coin.Amount
		return false
	})
	return out
}

func balOf(m map[string]math.Int, k string) math.Int {
	if v, ok := m[k]; ok {
		return v
	}
	return math.ZeroInt()
}

// diffAll prints every (address, denom) pair whose balance changed.
func (s *ConservationSuite) diffAll(before, after map[string]math.Int) string {
	var sb strings.Builder
	keys := make(map[string]bool, len(before)+len(after))
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	n := 0
	for k := range keys {
		b, a := balOf(before, k), balOf(after, k)
		if !b.Equal(a) {
			fmt.Fprintf(&sb, "  %s: %s -> %s (delta %s)\n", k, b, a, a.Sub(b))
			n++
			if n > 40 {
				fmt.Fprintf(&sb, "  ...truncated\n")
				break
			}
		}
	}
	return sb.String()
}

func (s *ConservationSuite) supplyTable() string {
	var sb strings.Builder
	s.App.BankKeeper.IterateTotalSupply(s.Ctx, func(coin sdk.Coin) bool {
		fmt.Fprintf(&sb, "  supply %s = %s\n", coin.Denom, coin.Amount)
		return false
	})
	return sb.String()
}

func (s *ConservationSuite) check(tag string) {
	for _, denom := range []string{"TokenA", "TokenB"} {
		require.Equalf(s.T(), s.startSupply[denom].String(), s.chainTotal(denom).String(),
			"VALUE CREATED/DESTROYED for %s at %s", denom, tag)
		require.Equalf(s.T(), s.App.BankKeeper.GetSupply(s.Ctx, denom).Amount.String(),
			s.chainTotal(denom).String(),
			"BANK INCONSISTENT: %s supply != sum of balances at %s", denom, tag)
	}
}

func (s *ConservationSuite) randAmt() math.Int {
	return math.NewInt(1 + s.rng.Int63n(500_000)).Mul(denomMultiple)
}

func (s *ConservationSuite) randDec() mathutils.PrecDec {
	return mathutils.NewPrecDecFromInt(math.NewInt(1 + s.rng.Int63n(3_000_000)))
}

// ---------------------------------------------------------------- actions

func (s *ConservationSuite) oneAction(a sdk.AccAddress) string {
	switch s.rng.Intn(7) {
	case 0: // multi-tick deposits (balanced and imbalanced)
		ok := s.runTx(func() error {
			_, err := s.ms.Deposit(s.Ctx, &types.MsgDeposit{
				Creator: a.String(), Receiver: a.String(),
				TokenA: "TokenA", TokenB: "TokenB",
				AmountsA:        []math.Int{s.randAmt(), math.ZeroInt(), s.randAmt()},
				AmountsB:        []math.Int{math.ZeroInt(), s.randAmt(), s.randAmt()},
				TickIndexesAToB: []int64{-20, -20, 40},
				Fees:            []uint64{20, 50, 20},
				Options:         []*types.DepositOptions{{}, {}, {}},
			})
			return err
		})
		return fmt.Sprintf("deposit(ok=%v)", ok)
	case 1: // multi-hop swap both directions with random exit limits
		tokenIn, tokenOut := "TokenA", "TokenB"
		if s.rng.Intn(2) == 1 {
			tokenIn, tokenOut = "TokenB", "TokenA"
		}
		ok := s.runTx(func() error {
			_, err := s.ms.MultiHopSwap(s.Ctx, &types.MsgMultiHopSwap{
				Creator:  a.String(),
				Receiver: a.String(),
				Routes: []*types.MultiHopRoute{
					{Hops: []string{tokenIn, tokenOut}},
					{Hops: []string{tokenIn, "TokenA", tokenOut}},
				},
				AmountIn:       s.randAmt(),
				ExitLimitPrice: s.randDec(),
				PickBestRoute:  s.rng.Intn(2) == 1,
			})
			return err
		})
		return fmt.Sprintf("multihopswap(ok=%v)", ok)
	case 2: // maker GTC order A->B at a random tick
		ok := s.runTx(func() error {
			_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
				Creator:          a.String(),
				Receiver:         a.String(),
				TokenIn:          "TokenA",
				TokenOut:         "TokenB",
				AmountIn:         s.randAmt(),
				TickIndexInToOut: s.rng.Int63n(401) - 200,
				OrderType:        types.LimitOrderType_GOOD_TIL_CANCELLED,
			})
			return err
		})
		return fmt.Sprintf("placeGTC_AtoB(ok=%v)", ok)
	case 3: // maker GTC order B->A with a random limit sell price
		lsp := s.randDec()
		ok := s.runTx(func() error {
			_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
				Creator:        a.String(),
				Receiver:       a.String(),
				TokenIn:        "TokenB",
				TokenOut:       "TokenA",
				AmountIn:       s.randAmt(),
				OrderType:      types.LimitOrderType_GOOD_TIL_CANCELLED,
				LimitSellPrice: &lsp,
			})
			return err
		})
		return fmt.Sprintf("placeGTC_BtoA(ok=%v)", ok)
	case 4: // taker FOK order
		lsp := s.randDec()
		ok := s.runTx(func() error {
			_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
				Creator:        a.String(),
				Receiver:       a.String(),
				TokenIn:        "TokenB",
				TokenOut:       "TokenA",
				AmountIn:       s.randAmt(),
				OrderType:      types.LimitOrderType_FILL_OR_KILL,
				LimitSellPrice: &lsp,
			})
			return err
		})
		return fmt.Sprintf("placeFOK_BtoA(ok=%v)", ok)
	case 5: // withdraw everything from pools
		return fmt.Sprintf("withdrawPools(ok=%v)", s.drainPools(a))
	case 6: // claim filled limit orders / cancel unfilled ones
		return fmt.Sprintf("claimOrders(ok=%v)", s.drainOrders(a))
	}
	return "noop"
}

func (s *ConservationSuite) drainPools(a sdk.AccAddress) bool {
	balances := s.App.BankKeeper.GetAllBalances(s.Ctx, a)
	shareCoins := sdk.Coins{}
	for _, c := range balances {
		if strings.HasPrefix(c.Denom, types.PoolDenomPrefix) {
			shareCoins = shareCoins.Add(c)
		}
	}
	if shareCoins.Empty() {
		return true
	}
	return s.runTx(func() error {
		_, err := s.ms.WithdrawalWithShares(s.Ctx, &types.MsgWithdrawalWithShares{
			Creator:        a.String(),
			Receiver:       a.String(),
			SharesToRemove: shareCoins,
		})
		return err
	})
}

func (s *ConservationSuite) drainOrders(a sdk.AccAddress) bool {
	allOK := true
	for _, tu := range s.App.DexKeeper.GetAllLimitOrderTrancheUserForAddress(s.Ctx, a) {
		if tu == nil || tu.TrancheKey == "" {
			continue
		}
		key := tu.TrancheKey
		addr := a.String()
		cancelled := s.runTx(func() error {
			_, err := s.ms.CancelLimitOrder(s.Ctx, &types.MsgCancelLimitOrder{Creator: addr, TrancheKey: key})
			return err
		})
		if cancelled {
			continue // cancel pays out whatever was left
		}
		ok := s.runTx(func() error {
			_, err := s.ms.WithdrawFilledLimitOrder(s.Ctx, &types.MsgWithdrawFilledLimitOrder{
				Creator: addr, TrancheKey: key,
			})
			return err
		})
		if !ok {
			// A record whose shares are already exhausted legitimately has nothing
			// left to claim; anything else means an unhonourable claim.
			cur, found := s.App.DexKeeper.GetLimitOrderTrancheUser(s.Ctx, addr, key)
			if found && cur.SharesOwned.IsPositive() {
				s.T().Logf("UNPAYABLE claim: user %s tranche %s sharesOwned=%s",
					addr, key, cur.SharesOwned)
			}
			allOK = false
		}
	}
	return allOK
}

// ---------------------------------------------------------------- reporting

func (s *ConservationSuite) poolSummary() string {
	var sb strings.Builder
	count := s.App.DexKeeper.GetPoolCount(s.Ctx)
	for id := uint64(0); id < count; id++ {
		pool, found := s.App.DexKeeper.GetPoolByID(s.Ctx, id)
		if !found {
			continue
		}
		poolDenom := pool.GetPoolDenom()
		totalShares := s.App.BankKeeper.GetSupply(s.Ctx, poolDenom).Amount
		held := math.ZeroInt()
		s.App.BankKeeper.IterateAllBalances(s.Ctx, func(_ sdk.AccAddress, coin sdk.Coin) bool {
			if coin.Denom == poolDenom {
				held = held.Add(coin.Amount)
			}
			return false
		})
		var c0, c1 mathutils.PrecDec
		if totalShares.IsPositive() {
			c0, c1 = pool.RedeemValue(held, totalShares)
		}
		fmt.Fprintf(&sb, "  pool %d %s reserves0=%s reserves1=%s shares(held/supply)=%s/%s claim0=%s claim1=%s\n",
			id, pool.MustPairID().CanonicalString(),
			pool.LowerTick0.DecReservesMakerDenom, pool.UpperTick1.DecReservesMakerDenom,
			held, totalShares, c0, c1)
	}
	return sb.String()
}

// ---------------------------------------------------------------- test

func (s *ConservationSuite) TestDEXValueConservation() {
	const rounds = 150
	for r := 0; r < rounds; r++ {
		for _, a := range s.actors {
			beforeAll := s.allBalances()
			beforeTotA, beforeTotB := s.chainTotal("TokenA"), s.chainTotal("TokenB")
			act := s.oneAction(a)
			totA, totB := s.chainTotal("TokenA"), s.chainTotal("TokenB")
			if !totA.Equal(beforeTotA) || !totB.Equal(beforeTotB) {
				s.T().Logf("VALUE LEAK by %s doing %s at round %d: chainBalanceA %s->%s chainBalanceB %s->%s\nFULL BANK DIFF:\n%sSUPPLY:\n%sPOOLS:\n%s",
					a, act, r, beforeTotA, totA, beforeTotB, totB,
					s.diffAll(beforeAll, s.allBalances()), s.supplyTable(), s.poolSummary())
				s.T().FailNow()
			}
			s.check(fmt.Sprintf("round %d actor %s action %s", r, a, act))
		}
	}

	// ---- quiescence: everyone exits as far as they can ----
	for pass := 0; pass < 30; pass++ {
		moved := false
		for _, a := range s.actors {
			beforeA, beforeB := s.supply("TokenA", a), s.supply("TokenB", a)
			s.drainPools(a)
			s.drainOrders(a)
			if !beforeA.Equal(s.supply("TokenA", a)) || !beforeB.Equal(s.supply("TokenB", a)) {
				moved = true
			}
		}
		if !moved {
			break
		}
	}

	// ---- invariant 2: full exit must be possible ----
	for _, a := range s.actors {
		require.Truef(s.T(), s.drainPools(a), "pool withdrawal not payable for %s", a)
		require.Truef(s.T(), s.drainOrders(a), "limit order claim not payable for %s", a)
		balances := s.App.BankKeeper.GetAllBalances(s.Ctx, a)
		for _, c := range balances {
			require.Falsef(s.T(), strings.HasPrefix(c.Denom, types.PoolDenomPrefix),
				"%s still holds un-withdrawable LP shares %s", a, c)
		}
	}

	// ---- invariant 3: nothing but rounding dust may remain in the module ----
	fb, err := s.App.DexKeeper.GetAllFractionalBalances(s.Ctx)
	require.NoError(s.T(), err)
	credits := map[string]math.Int{"TokenA": math.ZeroInt(), "TokenB": math.ZeroInt()}
	for _, c := range fb {
		if _, ok := credits[c.Denom]; ok {
			credits[c.Denom] = credits[c.Denom].Add(c.Amount.Ceil().TruncateInt())
		}
	}

	objects := map[string]int64{"TokenA": 0, "TokenB": 0}
	for _, tl := range s.App.DexKeeper.GetAllTickLiquidity(s.Ctx) {
		if tr := tl.GetLimitOrderTranche(); tr != nil {
			objects[tr.Key.TradePairId.MakerDenom]++
			objects[tr.Key.TradePairId.TakerDenom]++
		}
	}
	for _, t := range s.App.DexKeeper.GetAllInactiveLimitOrderTranche(s.Ctx) {
		objects[t.Key.TradePairId.MakerDenom]++
		objects[t.Key.TradePairId.TakerDenom]++
	}
	poolCount := int64(0)
	for id := uint64(0); id < s.App.DexKeeper.GetPoolCount(s.Ctx); id++ {
		if _, found := s.App.DexKeeper.GetPoolByID(s.Ctx, id); found {
			poolCount++
		}
	}

	for _, denom := range []string{"TokenA", "TokenB"} {
		stranded := s.modSupply(denom).Sub(credits[denom])
		limit := math.NewInt(int64(objects[denom]) + 2*poolCount + 2*int64(len(s.actors)))
		s.T().Logf("QUIESCENCE %s: module=%s fractionalCredits=%s stranded=%s dustBound=%s",
			denom, s.modSupply(denom), credits[denom], stranded, limit)
		require.LessOrEqualf(s.T(), stranded.String(), limit.String(),
			"STRANDED VALUE in dex module for %s: %s > dust bound %s", denom, stranded, limit)
	}
	s.check("final")

	for _, a := range s.actors {
		s.T().Logf("FINAL %s: A=%s B=%s", a, s.supply("TokenA", a), s.supply("TokenB", a))
	}
	s.T().Logf("FINAL module: A=%s B=%s\nPOOLS:\n%s", s.modSupply("TokenA"), s.modSupply("TokenB"), s.poolSummary())
}
