# Auditoría de seguridad — Neutron L1 (stack de la fundación)

Commit auditado: `9195772be6266b309739e09bfd28780c411b5e96` (main, `neutron-org/neutron`, repo archivado / modo mantenimiento; árbol `5cabbfe084b2e230d55e61acc9853a33c5a52dd0`).
Fecha: 2026-11-12. Auditor: agente Arena (modo agente, repo clonado en `/home/user/neutron`).

---

## 0. Veredicto

**No crítico en código** para el superficie en scope (lógica de cadena de Neutron: `x/*`, `wasmbinding`, `app`, más los forks de `cosmos-sdk`, `wasmd`, `feemarket`, `connect`, `ibc-go` y el contrato contraparte `rate-limiter-contract`).

No encontré ningún bug que cumpla los 4 criterios exigidos a la vez (bug concreto en código de producción + permissionless + alcanzable por entrada activa con configuración real del repo + PoC o matemática exacta donde el atacante mete X y saca Y > X extrayendo la diferencia de pools/bóvedas/usuarios).

Construí **10 vectores de ataque concretos** contra el código de producción (los más serios: embalse/desacople de suministro ICS20 en `x/ibc-hooks`, confusión de denoms entre pares en `x/dex` al retirar LP shares, destrucción asimétrica de dust en el `FractionalBanker`, cancelaciones/retiros sin control de propiedad, mutación de estado desde queries, bypass del rate limiter, `SubmitQueryResult` forjado). **Todos quedaron refutados con evidencia de código**, y §4 documenta la refutación de cada uno con su cita exacta, para que no se re-pise. Las matemáticas del DEX (compartido con la rama auditada en `chore/fix_price_calc`, `chore/better_tranche_share_calc`, `dex-audit-branch`) aguantaron además un fuzz de conservación ejecutado en CI con 5 seeds (§3).

La verificación fue posible porque el repo incluye las guards correctas en los sitios donde yo esperaba no encontrarlas: `ErrCanOnlyWithdrawFromSamePair` (`x/dex/keeper/withdraw.go:170-179`), descarte de estado en ack de error (`ibc-go` v10.5.0 `modules/core/keeper/msg_server.go:463-472`), búsqueda del registro de orden por `callerAddr` (`x/dex/keeper/cancel_limit_order.go:60-63`) y `CacheContext()` en las queries `Simulate*`.---

## 1. Cobertura: repos clonados y pins exactos (prerequisito del encargo)

Organización responsable del stack: **`neutron-org`** (verificada por API: 68 repos públicos, **0 privados accesibles**; `neutron-org/neodynamic` no existe → 404). `neutron` está **archivado** (2026-07-14), por lo que el HEAD de `main` es el código de producción vigente; el tag `v11.1.0` (`c8c56117…`) es alcanzable solo vía upstream.

| Componente (pin real usado por `go.mod` / `Dockerfile` de producción) | Repo | Commit |
|---|---|---|
| Cadena auditada (x/dex, x/ibc-hooks, x/ibc-rate-limit, x/contractmanager, x/interchainqueries, x/interchaintxs, x/transfer, x/coinfactory, x/tokenfactory, x/globalfee, x/dynamicfees, x/feemarket wiring, x/feerefunder, x/cron, x/state-verifier, x/gmp, x/crypto, wasmbinding, app) | `neutron-org/neutron` | `9195772be6266b309739e09bfd28780c411b5e96` |
| `cosmos-sdk` fork | `neutron-org/cosmos-sdk` | `9aff5996…` (v0.53.4-neutron) |
| `wasmd` fork | `neutron-org/wasmd` | `3c1a6b2b…` (v0.61.14-neutron; diff contra upstream v0.61.0 = solo `x/wasm/client/cli/genesis_msg.go`) |
| `feemarket` | `neutron-org/feemarket` | `f0e55c2c…` (v1.2.0) |
| `connect` (ICA relayer) | `neutron-org/connect` | `f92a934a…` (v1.3.1) |
| `wasmvm` | `CosmWasm/wasmvm` | `b9babce5…` (v3.0.7) |
| `ibc-go` | `cosmos/ibc-go` | v10.5.0 (tarball codeload → `/home/user/clones/ibc-go-upstream`; `neutron-org/ibc-go` **no tiene tags**: 0) |
| `testnets` (génesis de producción) | `neutron-org/testnets` | `c63b0bde…` |
| Contrato contraparte del rate limiter | `neutron-org/rate-limiter-contract` | `7728a75d385e2597566d0caeb9e47385edcf6b15` (2024-10-01, punta de `main`) |
| SDK de ejemplos Neutron | `neutron-org/neutron-sdk` | `82b2e86…` |
| Contratos de desarrollo | `neutron-org/neutron-dev-contracts` | `d421391…` |
| Vesting / TGE (contratos de producción) | `neutron-org/vesting-contracts` / `neutron-org/neutron-tge-contracts` | `515b2ea` / `92ed330` |
| Modelo de referencia del DEX | `neutron-org/dex-quint-model` | `c76e016` |
| Ecosistema (fallback, **no auditado**, ver §6) | `astroport-fi/astroport-core` | `c68a9fda725ff7c5782cd1a0d1e0a52465b07633` |

El repo no tiene submódulos (`.gitmodules` ausente) y `contracts/` está vacío; no hay LFS que traer.

### Mapa de componentes/direcciones/parámetros de producción (derivado del repo, sin RPC)

Fuente: `network/`, `scripts/`, `app/app.go`, `app/upgrades/*`, `x/*/types/params.go`, y `testnets/neutron-1/neutron-genesis-without-ccv.json` (parsing con Python):

- 74 `gen_msgs` de wasm: `code_id` → contrato: DAO (`neutron-dao-proposal`), 4 vaults de votación, 3 multisigs, suite TGE (vesting/merkle/allocator), oráculos `cw-band-price-feed` con `oracle_script_id = 3`, oráculos TWAP de Astroport USDC/ATOM.
- **Toda** autoridad de módulo (`x/dex`, `x/ibc-rate-limit`, `x/cron`, `x/feerefunder`, `x/interchainqueries`, `x/interchaintxs`, `x/globalfee`, `x/dynamicfees`, `x/coinfactory`, `x/tokenfactory`) = `neutron10ur0l2yten8wh9ykcjxzx9fwwflkpy965mr4kt` (cuenta de `gov`) → ningún `UpdateParams` es permissionless.
- Cuentas de módulo relevantes: `dex` (con `Minter|Burner`), `coinfactory`/`tokenfactory` (`Minter|Burner`), `feerefunder`, `contractmanager`, `cron`, `ibc-hooks` **no tiene cuenta de módulo ni keeper** (solo un `AccountKeeper` para queries), `feemarket` usa `FeeCollectorName` con permisos `nil` en `maccPerms` (`app/app.go:315`).
- Parámetros que activan/desactivan superficie (nombres verificados en el repo): `x/ibc-rate-limit` → `Params.ContractAddress` (`types/params.pb.go:28`, default `""` ⇒ middleware inerte hasta que gov lo fija); `x/dex` → `Params{FeeTiers, Paused, MaxJITsPerBlock, GoodTilPurgeAllowance, WhitelistedLps, WithdrawOnly}` (`types/params.go:15-25`, defaults `Paused=false`, `WithdrawOnly=false`, `FeeTiers=[0,1,2,3,4,5,10,20,50,100,150,200]`); `x/feerefunder` → `Params{FeeEnabled, MinFee}`; `x/interchaintxs` → `Params.RegisterFee` / `MsgSubmitTxMaxMessages` y la constante `ICARegistrationFeeFirstCodeID`; `x/globalfee` + `x/dynamicfees` (lanes en `app/lane.go`) para min gas prices. Ninguno de esos parámetros es modificable sin gov (`UpdateParams` con `GetAuthority()`), salvo `x/feerefunder.distribute*` que es interno.

---

## 2. Método y límite de ejecución (importante para leer el resto)

- **Sin RPC**: no se consultó balances ni estado de producción. Todo lo anterior sale de código clonado + génesis versionada en `testnets`. No se afirma TVL en ningún sitio.
- **Sin toolchain local**: el sandbox no tiene `go`, `cargo` ni `forge` (probeado; `pip install go/golang/rust` son señuelos, 3 GB RAM). Por tanto **no fue posible ejecutar PoC localmente**. El ejecutor de pruebas fue GitHub Actions sobre el propio repo (branch `arena/a4866816-neutron`, workflow `Audit CI` en `.github/workflows/audit-ci.yml`), que corre `go test` del commit exacto y sube el log a la rama huérfana `audit-results`.
- La única ejecución de código real de esta auditoría es, por tanto, **Go upstream-style `go test`** contra el árbol auditado (suite unitaria completa de los módulos relevantes + fuzz de invariantes propio descrito en §3), no `forge`/`hardhat`/`cargo test`. Esto está declarado explícitamente en el registro (§6).

---

## 3. Invariantes verificadas con prueba ejecutada: contabilidad del DEX (`x/dex`)

PoC: `x/dex/keeper/audit_conservation_test.go` (añadido por mí en este branch).

- Suite propia sobre `apptesting.KeeperTestHelper`, 8 actores con 1e12 de `TokenA` y 1e12 de `TokenB` cada uno. **No sobrescribo parámetros**: corre con los defaults del módulo (`x/dex/types/params.go:15-25` → `DefaultFeeTiers = [0,1,2,3,4,5,10,20,50,100,150,200]`, `Paused = false`, `WithdrawOnly = false`, `GoodTilPurgeAllowance` default), que son los que dejan todos los msgs habilitados; los depósitos del fuzz usan fees 20/50, incluidas en esa lista. Nota de configuración: `neutron-1` no trae estado de `dex` en el génesis clonado (`app_state.dex = {}`; el módulo llegó por upgrade), así que los `FeeTiers` en vigor los fijó gobernanza y **no** están en el repo — el resultado del fuzz es independiente de esa lista porque la invariantes son de conservación, no de precio.
- Cada mensaje se ejecuta dentro de su propio `CacheContext()` y **solo se commitea si el handler devuelve `nil`**, replicando la atomicidad real de `DeliverTx` (la suite no envuelve en tx; sin esto, un error de handler deja estado parcialmente aplicado — ese artefacto fue la causa de los dos "leaks" que reporté en iteraciones anteriores; ahora está corregido y no hay ningún hallazgo falso que retirar: ver §5 "falsos positivos eliminados").
- 5 seeds × ~1 180 acciones = **5 909 acciones**, **3 547** msgs cometidos con éxito (≈2 362 rechazados legítimamente por validaciones), **6 005** checkpoints invariantes.

Invariantes duras, todas en verde en los 5 seeds:

1. **Conservación de valor**: para cada denom, la suma *global* de balances del banco (iteración completa de `IterateAllBalances`, no solo las cuentas seguidas) es exactamente constante tras cada acción. Ni un solo evento de creación o destrucción de valor.
2. **Auto-consistencia del banco**: `BankKeeper.GetSupply(denom) == Σ balances(denom)` en cada checkpoint. (Esta es la que delataba el artefacto del harness en v1/v2.)
3. **Salida completa posible**: alquietud tras hasta 30 pasadas de drenaje; después, **todo** LP share de **todo** actor es canjeable y **toda** reclamación de tranche es pagadera sin que el módulo se quede corto (ningún `insufficient funds`).
4. **Cero valor embalsado**: al final, `balance del módulo − Σ créditos fraccionales` = **0** para `TokenA` y `TokenB` en los 5 seeds (cota de dust permitida: 22). Es decir, tras la salida masiva no queda ni una unidad atrapada: la contabilidad del `FractionalBanker` (`x/dex/keeper/fractional_banker.go`) cierra exactamente, incluyendo el truncado de dust.

Salida literal (seeds 1337 / 90210 / 424242 / 7 / 20261112; idéntica estructura en `results/11-gotest.log` y `results/12-gotest.log`):

```
QUIESCENCE TokenA: module=5 fractionalCredits=5 stranded=0 dustBound=22
QUIESCENCE TokenB: module=5 fractionalCredits=5 stranded=0 dustBound=22
AUDIT SUMMARY seed=1337 actions=1176 committed=704 invariantChecks=1201
...
AUDIT SUMMARY seed=20261112 actions=1160 committed=652 invariantChecks=1201
--- PASS: TestDEXValueConservationFuzz (0.77s)
```

Combinado con la suite unitaria completa en verde (§6), esto cubre con ejecución las rutas matemáticas de mayor riesgo del DEX: `CalcSharesMinted`/`RedeemValue`/`Withdraw` (`x/dex/types/pool.go:183/209/230`), `CalcAutoswapAmount`/`CalcAutoswapFee` (`:299`), `LimitOrderTranche.Swap/RemoveTokenIn/CalcWithdrawAmount/Withdraw` (`x/dex/types/limit_order_tranche.go:135-230`), `AmountUnfilled` (`:126`), y el banco fraccional (`RoundDownToWholeTokenAmounts`, `CalcUserSendMinusDebts`). En todas ellas la dirección de redondeo favorece al pool, y ningún camino de msg produce sobre-claim sostenido.

---

## 4. Vectores candidatos construidos y refutados (con la verificación que los mata)

Cada entrada es un vector que llegué a creer viable, con su ruta de entrada permissionless y el hecho concreto de código que lo invalida. Ninguno sobrevive; los dejo documentados porque son precisamente los puntos donde este código se rompe si alguien quita la guarda citada.

**V1 — `x/ibc-hooks`: ack de error *después* de acreditados los fondos ⇒ ¿fondos embalsados en la cuenta pin + suministro `ibc/*` sin respaldo?**
La hipótesis: `x/ibc-hooks/wasm_hook.go:79` reescribe `data.Receiver` hacia `DeriveIntermediateSender` (`x/ibc-hooks/utils/utils.go:66-70`, prefijo `"ibc-wasm-hook-intermediary"` en `x/ibc-hooks/types/keys.go:8`), la línea 87 ejecuta la app de transferencia (que acredita), y si la llamada al contrato falla (`:110-112`) se devuelve un **ack de error** sin revertir el crédito; como `ibc-go` reembolsa al remitente en la cadena de origen (`modules/apps/transfer/keeper/relay.go:212-232`, llamada a `refundPacketTokens` en `:225`), el atacante quedaría con sus tokens **y** los vouchers minteados en la cuenta pin, sin ruta de salida (`x/ibc-hooks` no tiene keeper ni msgs: `sdkmodule.go:112`, `BeginBlock`/`EndBlock` vacíos en `:126,131`; solo un query de lectura en `client/cli/query.go:54`). La ruta está activa en producción: `app/app.go:655` → `WireICS20PreWasmKeeper` (`:1611-1682`) y `app/app.go:840` fija `Ics20WasmHooks.ContractKeeper = &app.WasmKeeper` sobre el mismo struct que consume el middleware, así que `ProperlyConfigured()` (`wasm_hook.go:39-41`) es `true`; y basta un memo `{"wasm":{"contract":C,"msg":{}}}` con `C == receiver` y C **inexistente** para forzar el fallo (`wasmd` `x/wasm/keeper/keeper.go:1349` `ErrNoSuchContractFn`).
**REFUTADO**: el callback de aplicación se ejecuta dentro de un `CacheContext` cuyo `writeFn` **solo se invoca si el ack es nulo o exitoso** — `ibc-go` v10.5.0 `modules/core/keeper/msg_server.go:463-472` (función `RecvPacket`, `:428-492`):
```go
// Cache context so that we may discard state changes from callback if the acknowledgement is unsuccessful.
cacheCtx, writeFn = ctx.CacheContext()
ack := cbs.OnRecvPacket(cacheCtx, channelVersion, msg.Packet, relayer)
if ack == nil || ack.Success() {
    writeFn()
} else { /* sólo se re-emiten eventos de error */ }
```
Es decir, cuando `x/ibc-hooks` devuelve el ack de error en `wasm_hook.go:112`, el crédito de la línea 87 **nunca se persiste**: no hay vouchers huérfanos, no hay suministro sin respaldo, y el reembolso en la cadena de origen es exactamente consistente. Refuerzo: `WasmHooks` solo implementa `OnRecvPacketOverride` (`grep 'func (h WasmHooks) On'` → una sola coincidencia, `wasm_hook.go:43`); los `OnAcknowledgementPacket`/`OnTimeoutPacket` del middleware son pasadas limpias (`ibc_module.go:167-200`), así que el módulo nunca toca estado en el camino de ack/timeout y no hay replay posible desde ahí. El propio repo lo tiene testeado: `x/ibc-hooks/ibc_middleware_test.go:220-221` (`TestFundsAreReturnedOnFailedContractExec`, "If the wasm call fails, the contract acknowledgement should be an error and the funds returned"). Además no queda nada bloqueado: el core escribe el acknowledgement con el contexto externo (`msg_server.go:474-480`, `WriteAcknowledgement(ctx, msg.Packet, ack)`), así que el paquete consta como recibido con ack de error y el remitente se reembolsa normalmente. El único efecto de un hook fallido es el deseado (reembolso íntegro, cero estado en el destino); no hay secuencia colgada ni timeout que esperar, y por tanto ni siquiera un DoS temporal sobre el canal.

**V2 — `x/dex`: retiro de LP shares de dos pares distintos en un mismo `MsgWithdrawalWithShares` ⇒ pago en el denom equivocado (1:1) con robo a otros LPs.**
Ruta real: `WithdrawWithSharesCore` usa `poolsToRemoveFrom[0].MustPairID()` como par de *todos* los pools (`x/dex/keeper/withdraw.go:48`) y `ExecuteWithdraw` acumula `totalReserve0ToRemove/1` sumando las reservas propias de cada pool (`:115-159`), pagando después esos totales como `pairID.Token0`/`Token1` (`:80-95`). Si se admitieran pools de `(A,B)` y `(B,A)` en la misma msg, un LP con depósito unilateral barato en `(B,A)` cobraría ese saldo como `A` a 1:1, drenando el `A` de otros LPs del módulo.
**REFUTADO**: existe guarda explícita en `SharesToPools` — `x/dex/keeper/withdraw.go:170-179`: `if i > 0 && !pool.MustPairID().Equal(poolsToRemoveFrom[0].MustPairID()) → ErrCanOnlyWithdrawFromSamePair` (con el comentario "Safety check to ensure that all pools are from the same pair; this cannot be validated for MsgWithdrawalWithShares so it must be done here"). `MsgWithdrawalWithShares.Validate()` (`types/message_withdrawal_with_shares.go:46-71`) además exige importes positivos y parsea cada denom. La guarda está en el único sitio donde puede estar y mi fuzz la ejercitó (los LPs del fuzz sí tienen shares de los dos pares y los retiros conjuntos fallan limpiamente, como muestra el ratio 3 547/5 909 de msgs cometidos).

**V3 — `x/dex` `FractionalBanker`: `SetFractionalBalance` borra la clave cuando el saldo no es positivo** (`x/dex/keeper/fractional_banker.go:73-95`), así que no existe deuda negativa representable y el resto sub-token de un depósito se destruye; `CalcUserSendMinusDebts` (`:186-196`) redondea **hacia arriba** el pago del usuario (`userPaysRaw.Ceil()`), devolviéndole el exceso como crédito, y `RoundDownToWholeTokenAmounts` (`:141-156`) solo transfiere la parte entera.
Hipótesis: el módulo quedaría debiendo a terceros una cantidad agregada (over-promise) o acumularía valor ajeno.
**REFUTADO por medición**: el fuzz ejecuta depósitos/retiros con amounts aleatorios que producen truncados en cada acción y, a la alquietud, `balance del módulo − Σ créditos fraccionales = 0` exacto para ambos denoms en los 5 seeds, con `Σ balances == supply` en cada checkpoint y todas las reclamaciones pagaderas (§3). La pérdida de redondeo está acotada a <1 unidad por `(cuenta, denom)` y es autoinfligida por quien envía; no es amplifiable ni extraíble por un tercero.

**V4 — `x/ibc-rate-limit` + `rate-limiter-contract`: `blocking.rs` trata lista vacía de canales permitidos como PERMITIR** (`channels.is_empty()` ⇒ `Ok` temprano, y su propio test lo afirma), `undo_send` resta salida sin clave de deduplicación, `add_new_paths` guarda a ciegas (resetear `flow`/`channel_value`), `capacity()` muestrea `query_supply(local_denom)` en el primer transfer del periodo y `exceeds()` compara **flujo neto** (`balance_on(direction)`) en vez de bruto, `is_expired` usa `<` estricto, `pct` se topa a 100 con `min(..,100)`, `not_configured` = allow-all; el sudo `SendPacket` va con `destination.denom="omitted"` y `sequence:0` (el contrato ignora la secuencia ⇒ benigno).
**REFUTADO como crítico**: cada uno de esos handles está tras el RBAC del contrato, y **gov** tiene todos los roles desde `instantiate` (verificado en `rate-limiter-contract/src/rbac.rs` + sus tests). `ProcessMessages` es la única variante sin permiso (necesaria para avanzar la cola) y no altera límites; `RemoveMessage` está role-gado, así que el churn solo puede demorar mensajes encolados (`TIMELOCK_DELAY`), no saltárselos. Además el límite solo aplica si gov fija `x/ibc-rate-limit.Params.ContractAddress` (`types/params.pb.go:28`, default `""` ⇒ retorno temprano). No hay forma permissionless de ganar más que el slashing definido en el repo.

**V5 — `x/dex`: ¿cancelar o retirar la orden de otro?** `ExecuteCancelLimitOrder` obtiene el registro con `GetLimitOrderTrancheUser(ctx, callerAddr.String(), trancheKey)` (`keeper/cancel_limit_order.go:60-63`) ⇒ un no-owner recibe `ErrValidLimitOrderTrancheNotFound`; `RemoveTokenIn` topa en `DecReservesMakerDenom`, `CalcWithdrawAmount` topa en `DecReservesTakerDenom` y devuelve 0 si `shares <= 0`; `Cancel` marca 100 % retirado y borra el `TrancheUser`, y `AmountUnfilled`/`RatioFilled` están acotados (`types/limit_order_tranche.go:126-155`). No hay doble pago (comprobado también por el fuzz, que intercala `Cancel` y `WithdrawFilledLimitOrder` sobre las mismas tranches hasta el agotamiento).

**V6 — `x/dex`: queries que mutan.** `grpc_query_simulate_withdrawal.go:14-15,64-65`, `grpc_query_simulate_withdraw_filled_limit_order.go` y compañía llaman a `ExecuteWithdraw`/`ExecuteSwap` — que escriben pools/tranches — pero siempre sobre `ctx.CacheContext()` con el `writeFn` descartado. Sin mutación persistible desde query (ni desde el `wasmbinding` que reusa esas queries).

**V7 — `x/interchainqueries`: `SubmitQueryResult` es abierto al relayer**, pero `keeper/process_block_results.go:95-215` re-deriva y verifica el estado de consenso del counterparty (`types/verify.go`), comprueba `checkLastRemoteHeight` y `len(KvResults)==len(Keys)` antes de aplicar nada; `RemoveQuery` exige `ValidateRemoval(sender)` y `UpdateQuery` exige `query.Owner == sender`. `deterministicExecTxResult` normaliza el `tx_result` antes de comprometer el hash, así que no hay ambigüedad de compromiso. Sin ruta de robo ni de envenenamiento de estado.

**V8 — `x/dex`: `AssertCanPlaceJIT` se evalúa después de escribir la tranche** (`keeper/place_limit_order.go`). Su violación solo consume gas del propio llamante: por atomicidad de `DeliverTx` el writeset se descarta; no hay efecto contable.

**V9 — `app/ante_handler.go:88-111` `FeeDecoratorWithSwitch`**: el doc describe un switch a `feemarket` según `params.Enabled`, pero `AnteHandle` siempre corre `globalfee → ante.DeductFeeDecorator` y nunca instala el ante handler de feemarket; `maccPerms[feemarkettypes.FeeCollectorName] = nil` (`app/app.go:315`) y ningún módulo Neutron lee precios de gas de feemarket (el módulo sí corre en Begin/EndBlock, `app.go:947,985`). Es cableado/documentación muerta: afecta a la economía de fees (spam), no a fondos de pools/usuarios, y no hay PnL para un atacante. **No es vulnerabilidad bajo tus criterios.**

**V10 — dos "leaks" que reporté y retiro**: el `over-promise for TokenA` (`results/3`) y el `VALUE LEAK / delta −1 368 080 093 065 TokenA` (`results/4`-`results/9`) eran artefactos de mi harness: `apptesting` no envuelve en tx, así que un handler que falla dejaba aplicado el estado previo al error (reservas reducidas, `BurnShares` aplicado, etc.). Al emular `DeliverTx` (cache-ctx + `write()` solo con `err == nil`) ambos síntomas desaparecieron y `Σ balances == supply` pasó a cumplirse en cada checkpoint. También contribuyó mi propia definición de `claims()` (contaba el lado maker de tranches inactivas, que por diseño queda atrapado en el módulo tras `maxTrancheLifespan`, y espejos de `TickLiquidity` que ya viven dentro de `Pool.LowerTick0/UpperTick1`). **Ninguno es bug del producto.**

## 5. Rutas críticas revisadas a fondo (sin hallazgo)

| Área | Evidencia leída | Conclusión |
|---|---|---|
| `x/dex` guards de pausa | `keeper/msg_server.go:36,40,96,140,174,178,234,265,296,328` | `AssertNotPaused` en todos los msgs; `AssertNotWithdrawOnly` en Swap/MultiHop/Deposit pero no en retiros (intencional); `UpdateParams` por autoridad |
| Tranches: doble pago | `types/limit_order_tranche.go:126-230`, `keeper/cancel_limit_order.go:53-137`, `keeper/withdraw_filled_limit_order.go` | `Cancel` busca el registro por `callerAddr` (`GetLimitOrderTrancheUser(ctx, caller.String(), key)`) ⇒ no se puede cancelar la orden de otro; `RemoveTokenIn` topa en `DecReservesMakerDenom`, `CalcWithdrawAmount` topa en `DecReservesTakerDenom` y devuelve 0 si shares ≤ 0; ambos mutan reservas + shares antes de guardar y `Cancel` marca 100% retirado |
| Retiros mixtos entre pares | `keeper/withdraw.go:145-190` | Existe guarda explícita `ErrCanOnlyWithdrawFromSamePair` en `SharesToPools` ⇒ el vector "suma reservas de (A,B) y (B,A) y paga en el Token0 del primer pool" está **parcheado** |
| Queries que mutan | `keeper/grpc_query_simulate_withdrawal.go:12-56,59-101`, `grpc_query_simulate_withdraw_filled_limit_order.go` | Todas envueltas en `ctx.CacheContext()` con `write` descartado ⇒ sin mutación persistente desde query |
| JIT / orden de asserts | `keeper/place_limit_order.go` (`AssertCanPlaceJIT` tras escribir la tranche) | Solo gasto de gas en el bypass; sin efecto contable por atomicidad de tx |
| `x/ibc-rate-limit` | `rate_limit.go`, `ics4_wrapper.go`, `ibc_module.go`, `types/params.go` + lectura completa del contrato | Contabilidad por **flujo neto** (`balance_on(direction)`), `capacity = valor_de_canal * pct/100`, `min(…,100)`, `is_expired` estricto, `not_configured` ⇒ allow-all. `SendPacket` sudo va con `denom:"omitted"`, `sequence:0` y el contrato ignora la secuencia (benigno). El límite de entrada se consume antes de la ejecución y **no** se devuelve si la app falla luego (conservador, no inseguro) |
| `x/ibc-hooks` pila de recv | `wasm_hook.go:43-121`, `ibc_module.go`, `ics4_middleware.go`, `sdkmodule.go:112,126,131`, `utils/utils.go:44-70` | Memo validado (`validateAndParseMemo:166-221`: exige `wasm.contract == receiver` y `wasm.msg` mapa); el único hook implementado es `OnRecvPacketOverride`; el `funds` del `ExecuteContract` es exactamente `data.Amount` del denom local, de modo que un contrato solo puede recibir lo que el paquete trajo (nada de retirar el saldo acumulado de la cuenta pin); el fracaso del hook produce descarte de estado por core IBC (V1) |
| `x/contractmanager` | `ibc_middleware.go`, `keeper/{sudo,msg_server,failure}.go` | Límite de sudo por contrato y cola de fallos; `ReplayStargate` requiere que el reply exista; no mueve fondos |
| `x/interchaintxs` | `keeper/msg_server.go:1-150`, `keeper.go` (`ChargeFee`) | Ambos msgs exigen `HasContractInfo(sender)` (solo contratos); `ChargeFee` = `fee.IsAnyGTE(RegisterFee)` + `SendCoins(payer→feeCollector)`; `RegisterFee` lo fija gov; `MsgSubmitTx` topa `len(msgs)` y bloquea fees de ack/timeout |
| `x/feerefunder` | `keeper/keeper.go:59-200`, `msg_server.go:26` | Único msg es `UpdateParams` (autoridad). `LockFees` guarda/traslada y exige `checkFees` + canal existente; `Distribute{Ack,Timeout}Fee` solo paga al `receiver` (dueno del packet) y devuelve el fee no usado al `feeInfo.Payer`, borra el `FeeInfo` (no hay doble pago: ibc-go garantiza ack XOR timeout por secuencia). Pánico en `distributeFee` falla el tx del relayer (no corrompe estado) |
| `x/cron` | `keeper/msg_server.go:31,57,74` | `Schedule/Update/Remove` comparan `GetAuthority()` (gov) ⇒ el sudo reentrante solo puede apuntar a contratos registrados por gov; no es permissionless |
| `x/state-verifier` | `keeper/keeper.go:1-145` | `Verify` lee consenso en `height+1` y verifica contra `GetSDKSpecs()`; no está cableado como enforcement en ante/dynamicfees ⇒ no es ruta de ataque |
| `x/dynamicfees` / lanes | `keeper/*`, `app/lane.go` | Cálculo de min gas price por lane; sin contabilidad de fondos |
| `wasmbinding` | `stargate_allowlist.go`, `message_plugin.go:1-560` | Allowlist de Stargate estrecha; `x/dex`/`coinfactory`/`interchaintxs`/`contractmanager`/`feerefunder` msgs expuestos a contratos con las mismas guards del msg server |
| `app/upgrades` | `v11.1.0`, `v11.0.0` | v11.1.0 = solo `RunMigrations`, Added/Deleted vacíos; v11.0.0 quitó `adminmodule/harpoon/revenue/feeburner` y añadió `gov/mint/distribution` |
| Contratos de ejemplo del SDK | `neutron-sdk/contracts/{ibc_transfer,neutron_interchain_txs,neutron_interchain_queries}` | Demostrativos, sin auth (lo documentan ellos mismos); `revision_number: 2` y `untrn` hardcodeados ⇒ no son rutas de producción atacables |

---

## 6. Registro de auditoría

### 6.1 Repos clonados / commit exacto

Listado completo en §1 (13 repos + 2 repos de Astroport caracterizados). Clonación: `git clone --depth 1` en paralelo + `git fetch --depth 1 origin tag <pin>` cuando `go.mod` fijaba una versión concreta; verificación cruzada contra `go.sum`.

### 6.2 Config / génesis / deploy inspeccionados

- `testnets/neutron-1/neutron-genesis-without-ccv.json` (parseado con Python: 74 gen_msgs wasm, mapa code_id→contrato, authorities, `oracle_script_id=3`, parámetros de wasm)
- `neutron/network/*`, `neutron/scripts/*`, `neutron/app/app.go` (wiring completo), `neutron/app/upgrades/{v11.0.0,v11.1.0}/*`, `neutron/app/{ante_handler,post_handler,lane,genesis,config}.go`
- `x/*/types/params.go` de todos los módulos Neutron (valores por defecto y validaciones)
- `rate-limiter-contract/src/{contract.rs,lib.rs,state/*,packet.rs,rbac.rs,execute.rs,message_queue.rs,blocking.rs,testing/*}` (lectura completa, ~3 333 LOC)
- No existe `config.json` en `testnets/neutron-1`; el wiring v11 está en `app/app.go` (no hay `app/keepers/keepers.go`).

### 6.3 Tests / PoCs ejecutados (comandos y salida)

Todos los comandos corrieron en GitHub Actions sobre el commit auditado (workflow `Audit CI`, archivo `.github/workflows/audit-ci.yml` añadida por mí en el branch de auditoría; runner `ubuntu-latest`, Go `~1.24`; la etiqueta `ubicloud-standard-4` del repo padre nunca se programa en este fork).

1. **Suite unitaria completa de los módulos en scope** — run `43132524483` y run `43142617184`:
   ```
   VERSION=test go test -mod=mod -tags 'ledger test_ledger_mock' -timeout 50m \
     ./x/dex/... ./utils/... ./x/ibc-rate-limit/... ./x/contractmanager/... \
     ./x/feerefunder/... ./x/tokenfactory/... ./x/coinfactory/... \
     ./x/interchainqueries/... ./x/interchaintxs/... ./x/transfer/... \
     ./x/globalfee/... ./x/cron/... ./x/state-verifier/...
   ```
   Salida: **53 paquetes `ok`, 0 `FAIL`, 0 pánicos** en `results/2-gotest.log`; **61 paquetes `ok`, 0 `FAIL`, 0 pánicos** en `results/12-gotest.log` (añadido `./x/ibc-hooks/...`). Incluye el canary `utils/math/probe_audit_test.go` (añadido para probar que el runner ejecuta tests y los reporta; si el runner no corriera nada, el canary fallaría).
2. **Fuzz de invariantes del DEX (PoC propio)** — run `43141630636` y `43142617184`:
   ```
   AUDIT_SEED={1337,90210,424242,7,20261112} VERSION=test go test -mod=mod \
     -tags 'ledger test_ledger_mock' -v -run 'TestDEXValueConservationFuzz' ./x/dex/keeper/
   ```
   Salida: `--- PASS: TestDEXValueConservationFuzz` en los 5 seeds; `ok x/dex/keeper`; contadores `actions=1160..1202, committed=652..778, invariantChecks=1201` por seed; `stranded=0` para ambos denoms en los 5 seeds (`results/10-gotest.log`, `results/11-gotest.log`). El paquete `x/dex/keeper` completo (suite heredada + mi fuzz) pasó en `18.379s` (`results/10`).
3. **Ejecución de la suite del propio repo para el hook de IBC (refutación ejecutada de V1)** — run `43144428175`:
   ```
   VERSION=test go test -mod=mod -tags 'ledger test_ledger_mock' -v -run 'TestIBCHooksTestSuite' ./x/ibc-hooks/
   ```
   Resultado (`results/12-gotest.log`): `--- PASS: TestIBCHooksTestSuite (2.72s)` con sus 5 casos, incluido `TestFundsAreReturnedOnFailedContractExec` (ejecuta un `echo.wasm` real contra un memo cuyo msg el contrato rechaza y comprueba que **el contrato no recibe fondos** ante ack de error) y `TestFundsAreTransferredToTheContract` (caso de éxito). Qué prueba y qué no: el test ejecuta el escenario de fallo del hook y confirma que no hay pago al contrato; la ausencia de fondos embalsados en la cuenta pin la establishce la lectura de `msg_server.go:463-472` arriba (el writeFn no se invoca con ack de error), no la aserción del test.
4. Iteraciones del PoC (documentan el proceso de descarte de falsos positivos): runs `43134032164` (`results/3`), `43135246600` (`results/4`), `43136379466` (`results/5`), `43137379899` (`results/6`), `43138284574` (`results/7`), `43139238026` (`results/8`), `43140114409` (`results/9`). En `results/3` la **única** señal real fue "0 drift de suministro" (no se infló nada pese a 240 acciones con 4 actores).
5. Lectura estática adicional: `diff -r x/coinfactory x/tokenfactory`, `diff -rq wasmd-upstream clones/wasmd`, grep de `MintCoins|BurnCoins|SetBalance` en `x/dex`, grep de `DeriveIntermediateSender|SenderPrefix` en todo el repo (para probar que no hay ruta de recuperación de la cuenta pin).

### 6.4 Bloqueados / no cubiertos (no afirmo cobertura total)

- **`go test`/`cargo test`/`forge test` locales: BLOQUEADO** (sin toolchains en el sandbox, sin `go`/`cargo`/`forge`/`anvil`, 3 GB RAM). Sustituido por ejecución remota en Actions contra el commit exacto (limitación declarada en §2).
- **RPC de producción: no usado por mandato del encargo** ⇒ ningún balance, escrow, TVL ni estado live verificado. Todas las conclusiones de "configuración real" salen del repo y del génesis versionado.
- **`neutron-org/neutron` privado/ramas de seguridad**: no existen repos privados visibles; las ramas `dex-audit-branch`, `chore/fix_price_calc`, `chore/better_tranche_share_calc`, `feat/BEL_enforcement`, `chore/whitelist-tf-hooks` **no fueron diff-eadas** una a una (fuera de presupuesto).
- **Contratos desplegados en Neutron que no viven en `neutron-org`**: `cw-band-price-feed`, los oráculos TWAP y los contratos de Astroport/otras DAOs se identificaron por `gen_msgs`, pero su bytecode/fuente **no se auditó**.
- **Fallback de ecosistema: NO COMPLETADO.** Cloné y caractericé `astroport-fi/astroport-core` @ `c68a9fda…` y revisé solo su superficie de autorización de `pair`/`pair_concentrated` (`one_coin` + `ensure_eq!(denom, liquidity_token)` en `withdraw_liquidity`, `contracts/pair_concentrated/src/contract.rs:568-592`; owner-check de admin en `:867`) — sin hallazgo en ese vistazo. La matemática CLMM/xyk/stable, el manejo de posiciones por NFT (`UpdatePosition`/`IncreaseLiquidity`/`WithdrawLiquidity`) y los contratos de lending del ecosistema **no fueron auditados**, y no hay toolchain Rust local ni PoC ejecutado para ellos. Cualquier afirmación de "cobertura del stack DeFi de Neutron" quedaría fuera de lo que esta auditoría verificó.
- **`cosmos-sdk`/`ibc-go` upstream**: solo se auditó el *delta* del fork de Neutron (hooks de bank en `x/bank`, `x/wasm/client/cli/genesis_msg.go`) y la semántica de ack/refund de ICS20 en `relay.go`; no se re-auditó el core completo de ibc-go ni el de cosmos-sdk.
