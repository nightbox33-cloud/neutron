package keeper_test

// Audit PoC v2: value-conservation fuzz for the production DEX (x/dex @ neutron v11 HEAD).
//
// Global invariant checked after EVERY state-changing action:
//   total bank supply of TokenA/TokenB (all users + dex module account) is
//   EXACTLY constant -> the module can never mint value out of accounting.
//
// At quiescence, a full drain must be possible: every user can withdraw all
// of their pool shares, and claims must never fail with a bank
// "insufficient funds" error (module over-promise => real accounting bug).

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

	mathutils "github.com/neutron-org/neutron/v11/utils/math"
	"github.com/neutron-org/neutron/v11/testutil/apptesting"
	testutils "github.com/neutron-org/neutron/v11/x/dex/keeper/internal/testutils"
	dexkeeper "github.com/neutron-org/neutron/v11/x/dex/keeper"
	"github.com/neutron-org/neutron/v11/x/dex/types"
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

func (s *ConservationSuite) modAddr() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.ModuleName)
}

func (s *ConservationSuite) supply(denom string, addr sdk.AccAddress) math.Int {
	return s.App.BankKeeper.GetBalance(s.Ctx, addr, denom).Amount
}

func (s *ConservationSuite) modSupply(denom string) math.Int {
	return s.supply(denom, s.modAddr())
}

func (s *ConservationSuite) totalSupply(denom string) math.Int {
	total := s.modSupply(denom)
	for _, a := range s.actors {
		total = total.Add(s.supply(denom, a))
	}
	return total
}

func (s *ConservationSuite) check(tag string) {
	for _, denom := range []string{"TokenA", "TokenB"} {
		require.Equalf(s.T(), s.startSupply[denom].String(), s.chainTotal(denom).String(),
			"SUPPLY DRIFT for %s at %s", denom, tag)
	}
}

func (s *ConservationSuite) randAmt() math.Int {
	return math.NewInt(1 + s.rng.Int63n(500_000)).Mul(denomMultiple)
}

func (s *ConservationSuite) randDec() mathutils.PrecDec {
	return mathutils.NewPrecDecFromInt(math.NewInt(1 + s.rng.Int63n(3_000_000)))
}

// requireNoInsolvency fails the test if the error is a bank insolvency error,
// i.e. the module could not honor a legitimate claim.
func (s *ConservationSuite) requireNoInsolvency(err error, ctx string) {
	if err == nil {
		return
	}
	require.NotContainsf(s.T(), err.Error(), "insufficient funds",
		"MODULE INSOLVENT for claim at %s: %s", ctx, err.Error())
}

func (s *ConservationSuite) oneAction(a sdk.AccAddress) string {
	switch s.rng.Intn(7) {
	case 0: // multi-tick deposits (balanced and imbalanced)
		_, err := s.ms.Deposit(s.Ctx, &types.MsgDeposit{
			Creator: a.String(), Receiver: a.String(),
			TokenA: "TokenA", TokenB: "TokenB",
			AmountsA:        []math.Int{s.randAmt(), math.ZeroInt(), s.randAmt()},
			AmountsB:        []math.Int{math.ZeroInt(), s.randAmt(), s.randAmt()},
			TickIndexesAToB: []int64{-20, -20, 40},
			Fees:            []uint64{20, 50, 20},
			Options:         []*types.DepositOptions{{}, {}, {}},
		})
		_ = err
		return "deposit"
	case 1: // simple multi-hop swap both directions with random exit limits
		tokenIn, tokenOut := "TokenA", "TokenB"
		if s.rng.Intn(2) == 1 {
			tokenIn, tokenOut = "TokenB", "TokenA"
		}
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
		_ = err
		return "multihopswap"
	case 2: // maker GTC order A->B at random tick
		_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
			Creator:          a.String(),
			Receiver:         a.String(),
			TokenIn:          "TokenA",
			TokenOut:         "TokenB",
			AmountIn:         s.randAmt(),
			TickIndexInToOut: s.rng.Int63n(401) - 200,
			OrderType:        types.LimitOrderType_GOOD_TIL_CANCELLED,
		})
		_ = err
		return "placeGTC_AtoB"
	case 3: // maker GTC order B->A with random limit sell price
		lsp := s.randDec()
		_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
			Creator:        a.String(),
			Receiver:       a.String(),
			TokenIn:        "TokenB",
			TokenOut:       "TokenA",
			AmountIn:       s.randAmt(),
			OrderType:      types.LimitOrderType_GOOD_TIL_CANCELLED,
			LimitSellPrice: &lsp,
		})
		_ = err
		return "placeGTC_BtoA"
	case 4: // taker FOK order
		lsp := s.randDec()
		_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
			Creator:        a.String(),
			Receiver:       a.String(),
			TokenIn:        "TokenB",
			TokenOut:       "TokenA",
			AmountIn:       s.randAmt(),
			OrderType:      types.LimitOrderType_FILL_OR_KILL,
			LimitSellPrice: &lsp,
		})
		_ = err
		return "placeFOK_BtoA"
	case 5: // withdraw everything from pools (tolerant, keeps book churning)
		s.drainPools(a, false)
		return "withdrawPools"
	case 6: // claim filled limit orders / cancel unfilled
		s.drainOrders(a, false)
		return "claimOrders"
	}
	return "noop"
}

func (s *ConservationSuite) drainPools(a sdk.AccAddress, strict bool) {
	balances := s.App.BankKeeper.GetAllBalances(s.Ctx, a)
	shareCoins := sdk.Coins{}
	for _, c := range balances {
		if strings.HasPrefix(c.Denom, types.PoolDenomPrefix) {
			shareCoins = shareCoins.Add(c)
		}
	}
	if shareCoins.Empty() {
		return
	}
	_, err := s.ms.WithdrawalWithShares(s.Ctx, &types.MsgWithdrawalWithShares{
		Creator:        a.String(),
		Receiver:       a.String(),
		SharesToRemove: shareCoins,
	})
	if strict {
		require.NoErrorf(s.T(), err, "final pool drain failed for %s", a)
	}
}

func (s *ConservationSuite) drainOrders(a sdk.AccAddress, strict bool) {
	for _, tu := range s.App.DexKeeper.GetAllLimitOrderTrancheUserForAddress(s.Ctx, a) {
		if tu == nil || tu.TrancheKey == "" {
			continue
		}
		_, err := s.ms.CancelLimitOrder(s.Ctx, &types.MsgCancelLimitOrder{
			Creator: a.String(), TrancheKey: tu.TrancheKey,
		})
		if err == nil {
			continue // cancel already paid out everything left
		}
		_, err = s.ms.WithdrawFilledLimitOrder(s.Ctx, &types.MsgWithdrawFilledLimitOrder{
			Creator: a.String(), TrancheKey: tu.TrancheKey,
		})
		if strict {
			s.requireNoInsolvency(err, fmt.Sprintf("final order claim %s", tu.TrancheKey))
		}
	}
}

func (s *ConservationSuite) dumpState() [4]string {
	return [4]string{
		s.totalSupply("TokenA").String(),
		s.totalSupply("TokenB").String(),
		s.App.BankKeeper.GetSupply(s.Ctx, "TokenA").Amount.String(),
		s.App.BankKeeper.GetSupply(s.Ctx, "TokenB").Amount.String(),
	}
}

// holders returns every address holding a positive balance of denom.
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

// nameOf annotates an address with the module name if it is a module account.
func (s *ConservationSuite) nameOf(addr string) string {
	a, err := sdk.AccAddressFromBech32(addr)
	if err != nil {
		return addr
	}
	for name, p := range s.App.AccountKeeper.GetModulePermissions() {
		if p.GetAddress() != nil && p.GetAddress().Equals(a) {
			return name
		}
	}
	return addr
}

// diffHolders logs every address whose balance changed for a denom.
func (s *ConservationSuite) diffHolders(denom string, before, after map[string]math.Int) string {
	var sb strings.Builder
	for addr, b := range before {
		a, ok := after[addr]
		if !ok {
			a = math.ZeroInt()
		}
		if !b.Equal(a) {
			fmt.Fprintf(&sb, "  %s(%s) %s -> %s (delta %s)\n", s.nameOf(addr), addr, b, a, a.Sub(b))
		}
	}
	for addr, a := range after {
		if _, ok := before[addr]; !ok && !a.IsZero() {
			fmt.Fprintf(&sb, "  %s(%s) NEW holder %s\n", s.nameOf(addr), addr, a)
		}
	}
	return sb.String()
}

func (s *ConservationSuite) dump(tag string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s] module A=%s B=%s\n", tag, s.modSupply("TokenA"), s.modSupply("TokenB"))
	for _, a := range s.actors {
		fmt.Fprintf(&sb, "  actor %s A=%s B=%s\n", a, s.supply("TokenA", a), s.supply("TokenB", a))
	}
	return sb.String()
}

// strayHolders lists every TokenA/TokenB holder that is neither one of the
// fuzz actors nor the dex module account, i.e. who received the "vanished" value.
func (s *ConservationSuite) strayHolders() string {
	tracked := map[string]bool{s.modAddr().String(): true}
	for _, a := range s.actors {
		tracked[a.String()] = true
	}
	var sb strings.Builder
	for _, denom := range []string{"TokenA", "TokenB"} {
		for addr, amt := range s.holders(denom) {
			if !tracked[addr] {
				fmt.Fprintf(&sb, "  %s stray holder %s(%s) = %s\n", denom, s.nameOf(addr), addr, amt)
			}
		}
	}
	return sb.String()
}

func (s *ConservationSuite) TestDEXValueConservation() {
	const rounds = 150
	for r := 0; r < rounds; r++ {
		for _, a := range s.actors {
			for _, denom := range []string{"TokenA", "TokenB"} {
				// bank must be internally consistent at all times
				require.Equalf(s.T(), s.App.BankKeeper.GetSupply(s.Ctx, denom).Amount.String(),
					s.chainTotal(denom).String(), "BANK INCONSISTENT: %s supply != sum of balances (round %d)", denom, r)
			}
			beforeA := s.holders("TokenA")
			beforeB := s.holders("TokenB")
			beforeTotA, beforeTotB := s.chainTotal("TokenA"), s.chainTotal("TokenB")
			act := s.oneAction(a)
			totA, totB := s.chainTotal("TokenA"), s.chainTotal("TokenB")
			if !totA.Equal(beforeTotA) || !totB.Equal(beforeTotB) {
				s.T().Logf("VALUE LEAK by %s doing %s at round %d: chainBalanceA %s->%s chainBalanceB %s->%s\nA diff:\n%sB diff:\n%s",
					a, act, r, beforeTotA, totA, beforeTotB, totB,
					s.diffHolders("TokenA", beforeA, s.holders("TokenA")),
					s.diffHolders("TokenB", beforeB, s.holders("TokenB")))
				s.T().FailNow()
			}
			s.check(fmt.Sprintf("round %d actor %s", r, a))
		}
	}

	// ---- quiescence: repeated full drain until nothing moves anymore ----
	for pass := 0; pass < 25; pass++ {
		before := map[string]string{}
		for _, a := range s.actors {
			before[a.String()] = s.supply("TokenA", a).String() + "/" + s.supply("TokenB", a).String()
			s.drainPools(a, false)
			s.drainOrders(a, false)
		}
		changed := false
		for _, a := range s.actors {
			after := s.supply("TokenA", a).String() + "/" + s.supply("TokenB", a).String()
			if before[a.String()] != after {
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// ---- strict final drain: every remaining claim must be payable ----
	for _, a := range s.actors {
		s.drainPools(a, true)
		s.drainOrders(a, true)
	}
	s.check("final")

	// ---- fractional bank must be coverable by module funds ----
	fb, err := s.App.DexKeeper.GetAllFractionalBalances(s.Ctx)
	require.NoError(s.T(), err)
	owed := map[string]math.Int{"TokenA": math.ZeroInt(), "TokenB": math.ZeroInt()}
	for _, c := range fb {
		if _, ok := owed[c.Denom]; ok {
			owed[c.Denom] = owed[c.Denom].Add(c.Amount.Ceil().TruncateInt())
		}
	}
	for _, denom := range []string{"TokenA", "TokenB"} {
		require.LessOrEqualf(s.T(), owed[denom].String(), s.modSupply(denom).String(),
			"FRACTIONAL BANK INSOLVENT for %s: owed %s > module %s", denom, owed[denom], s.modSupply(denom))
	}

	for _, a := range s.actors {
		s.T().Logf("FINAL %s: A=%s B=%s", a,
			s.supply("TokenA", a), s.supply("TokenB", a))
	}
	s.T().Logf("FINAL module: A=%s B=%s", s.modSupply("TokenA"), s.modSupply("TokenB"))
}
