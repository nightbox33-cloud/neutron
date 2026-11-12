package keeper_test

// Audit PoC: value-conservation fuzz for the production DEX (x/dex, neutron v11).
// Invariants asserted after every action:
//  1. total supply of each token is EXACTLY constant (no inflation via accounting),
//  2. the dex module real balance >= sum of all outstanding tranche/pool claims,
//     i.e. the module can never be over-promised.
// Finally a fixed-point drain (withdraw all pool shares / filled limit orders /
// cancels) must converge, the module must remain solvent, and fractional bank
// debts must be coverable.

import (
	"fmt"
	"math/rand" //nolint:gosec // deterministic-enough fuzz driver for invariants
	"strings"
	"testing"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	mathutils "github.com/neutron-org/neutron/v11/utils/math"
	dexkeeper "github.com/neutron-org/neutron/v11/x/dex/keeper"
	"github.com/neutron-org/neutron/v11/x/dex/types"
)

type ConservationFuzzSuite struct {
	DexTestSuite
	ms          types.MsgServer
	startSupply map[string]math.Int
}

func TestDEXConservationFuzz(t *testing.T) {
	suite.Run(t, new(ConservationFuzzSuite))
}

func (s *ConservationFuzzSuite) SetupTest() {
	s.DexTestSuite.SetupTest()
	s.ms = dexkeeper.NewMsgServerImpl(s.App.DexKeeper)
	require.NoError(s.T(), s.App.DexKeeper.SetParams(s.Ctx, types.NewParams(
		[]uint64{1, 30, 100}, false, 25, 540_000, nil, false,
	)))
}

type cActor struct {
	name string
	addr sdk.AccAddress
}

func (s *ConservationFuzzSuite) actors() []cActor {
	return []cActor{
		{"alice", s.alice},
		{"bob", s.bob},
		{"carol", s.carol},
		{"dan", s.dan},
	}
}

func (s *ConservationFuzzSuite) modAddr() sdk.AccAddress {
	return authtypes.NewModuleAddress(types.ModuleName)
}

func (s *ConservationFuzzSuite) supply(denom string, addr sdk.AccAddress) math.Int {
	return s.App.BankKeeper.GetBalance(s.Ctx, addr, denom).Amount
}

func (s *ConservationFuzzSuite) modSupply(denom string) math.Int {
	return s.supply(denom, s.modAddr())
}

// claims: whole-token amounts that any user could currently pull out of the
// module via limit order tranches (active + inactive) and pool reserves.
func (s *ConservationFuzzSuite) claims(denom string) math.Int {
	claims := math.ZeroInt()

	addTranche := func(t *types.LimitOrderTranche) {
		if t == nil || t.Key == nil || t.Key.TradePairId == nil {
			return
		}
		if denom == t.Key.TradePairId.TakerDenom {
			claims = claims.Add(t.DecReservesTakerDenom.TruncateInt())
		}
		if denom == t.Key.TradePairId.MakerDenom {
			claims = claims.Add(t.DecReservesMakerDenom.TruncateInt())
		}
	}

	for _, l := range s.App.DexKeeper.GetAllTickLiquidity(s.Ctx) {
		if lor := l.GetLimitOrderTranche(); lor != nil {
			addTranche(lor)
		}
		if pr := l.GetPoolReserves(); pr != nil && pr.Key != nil && pr.Key.TradePairId != nil {
			if denom == pr.Key.TradePairId.MakerDenom {
				claims = claims.Add(pr.DecReservesMakerDenom.TruncateInt())
			}
		}
	}
	for _, t := range s.App.DexKeeper.GetAllInactiveLimitOrderTranche(s.Ctx) {
		addTranche(t)
	}
	return claims
}

func (s *ConservationFuzzSuite) checkInvariants(tag string) {
	for _, denom := range []string{"TokenA", "TokenB"} {
		total := s.supply(denom, s.alice).
			Add(s.supply(denom, s.bob)).
			Add(s.supply(denom, s.carol)).
			Add(s.supply(denom, s.dan)).
			Add(s.modSupply(denom))
		require.Equalf(s.T(), s.startSupply[denom].String(), total.String(),
			"supply drift for %s at %s: %s != %s", denom, tag, total, s.startSupply[denom])

		mod := s.modSupply(denom)
		cl := s.claims(denom)
		require.LessOrEqualf(s.T(), cl.String(), mod.String(),
			"module over-promised for %s at %s: claims %s > module %s", denom, tag, cl, mod)
	}
}

func (s *ConservationFuzzSuite) drainPools(addr sdk.AccAddress) bool {
	changed := false
	balances := s.App.BankKeeper.GetAllBalances(s.Ctx, addr)
	shareCoins := sdk.Coins{}
	for _, c := range balances {
		if strings.HasPrefix(c.Denom, types.PoolDenomPrefix) {
			shareCoins = shareCoins.Add(c)
		}
	}
	if shareCoins.Empty() {
		return false
	}
	_, err := s.ms.WithdrawalWithShares(s.Ctx, &types.MsgWithdrawalWithShares{
		Creator:        addr.String(),
		Receiver:       addr.String(),
		SharesToRemove: shareCoins,
	})
	if err == nil {
		changed = true
	}
	return changed
}

func (s *ConservationFuzzSuite) drainOrders(addr sdk.AccAddress) bool {
	changed := false
	for _, tu := range s.App.DexKeeper.GetAllLimitOrderTrancheUserForAddress(s.Ctx, addr) {
		if tu == nil || tu.TrancheKey == "" {
			continue
		}
		if _, err := s.ms.CancelLimitOrder(s.Ctx, &types.MsgCancelLimitOrder{
			Creator: addr.String(), TrancheKey: tu.TrancheKey,
		}); err == nil {
			changed = true
		}
		if _, err := s.ms.WithdrawFilledLimitOrder(s.Ctx, &types.MsgWithdrawFilledLimitOrder{
			Creator: addr.String(), TrancheKey: tu.TrancheKey,
		}); err == nil {
			changed = true
		}
	}
	return changed
}

func (s *ConservationFuzzSuite) TestDEXValueConservation() {
	s.fundAliceBalances(1_000_000, 1_000_000)
	s.fundBobBalances(1_000_000, 1_000_000)
	s.fundCarolBalances(1_000_000, 1_000_000)
	s.fundDanBalances(1_000_000, 1_000_000)

	s.startSupply = map[string]math.Int{}
	for _, denom := range []string{"TokenA", "TokenB"} {
		total := s.modSupply(denom)
		for _, a := range s.actors() {
			total = total.Add(s.supply(denom, a.addr))
		}
		s.startSupply[denom] = total
	}

	rng := rand.New(rand.NewSource(42)) //nolint:gosec
	randAmt := func() math.Int {
		return math.NewInt(1 + rng.Int63n(500_000)).Mul(denomMultiple)
	}
	randDec := func() mathutils.PrecDec {
		return mathutils.NewPrecDecFromInt(math.NewInt(1 + rng.Int63n(1_000_000)))
	}

	actors := s.actors()
	const rounds = 60

	for r := 0; r < rounds; r++ {
		for i, a := range actors {
			switch rng.Intn(6) {
			case 0: // balanced / imbalanced deposits across ticks and fees
				_, err := s.ms.Deposit(s.Ctx, &types.MsgDeposit{
					Creator: a.addr.String(), Receiver: a.addr.String(),
					TokenA: "TokenA", TokenB: "TokenB",
					AmountsA:        []math.Int{randAmt(), math.ZeroInt(), randAmt()},
					AmountsB:        []math.Int{math.ZeroInt(), randAmt(), randAmt()},
					TickIndexesAToB: []int64{-20, -20, 40},
					Fees:            []uint64{1, 30, 1},
					Options:         []*types.DepositOptions{{}, {}, {}},
				})
				_ = err
			case 1: // multi hop swaps with arbitrary exit limits
				tokenIn, tokenOut := "TokenA", "TokenB"
				if rng.Intn(2) == 1 {
					tokenIn, tokenOut = "TokenB", "TokenA"
				}
				_, err := s.ms.MultiHopSwap(s.Ctx, &types.MsgMultiHopSwap{
					Creator:  a.addr.String(),
					Receiver: a.addr.String(),
					Routes: []*types.MultiHopRoute{
						{Hops: []string{tokenIn, tokenOut}},
						{Hops: []string{tokenIn, "TokenA", tokenOut}},
					},
					AmountIn:     randAmt(),
					ExitLimitPrice: randDec(),
					PickBestRoute: rng.Intn(2) == 1,
				})
				_ = err
			case 2, 3: // maker GTC orders at random ticks
				_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
					Creator:  a.addr.String(),
					Receiver: a.addr.String(),
					TokenIn:  "TokenA", TokenOut: "TokenB",
					AmountIn:         randAmt(),
					TickIndexInToOut: rng.Int63n(401) - 200,
					OrderType:        types.LimitOrderType_GOOD_TIL_CANCELLED,
				})
				_ = err
				if err == nil && rng.Intn(2) == 1 {
					s.drainOrders(a.addr)
				}
			case 4: // taker FOK order the other direction
				_, err := s.ms.PlaceLimitOrder(s.Ctx, &types.MsgPlaceLimitOrder{
					Creator:  a.addr.String(),
					Receiver: a.addr.String(),
					TokenIn:  "TokenB", TokenOut: "TokenA",
					AmountIn:         randAmt(),
					TickIndexInToOut: -(rng.Int63n(401) - 200),
					OrderType:        types.LimitOrderType_FILL_OR_KILL,
				})
				_ = err
			default: // withdraw pools + claim filled orders
				s.drainPools(a.addr)
				s.drainOrders(a.addr)
			}
			s.checkInvariants(fmt.Sprintf("round %d actor %d", r, i))
		}
	}

	// ---- fixed point drain: everybody claims everything they can ----
	for pass := 0; pass < 40; pass++ {
		changed := false
		for _, a := range actors {
			if s.drainPools(a.addr) {
				changed = true
			}
			if s.drainOrders(a.addr) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	s.checkInvariants("final")

	// the fractional bank must also be coverable by module funds
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
			"fractional bank insolvent for %s: owed %s > module %s", denom, owed[denom], s.modSupply(denom))
	}

	for _, a := range actors {
		s.T().Logf("FINAL %s: A=%s B=%s", a.name,
			s.supply("TokenA", a.addr), s.supply("TokenB", a.addr))
	}
	s.T().Logf("FINAL module: A=%s B=%s", s.modSupply("TokenA"), s.modSupply("TokenB"))
}
