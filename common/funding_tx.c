#include "funding_tx.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/ptrint/ptrint.h>
#include <common/permute_tx.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      u64 change_satoshis,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	u8 *wscript;
	struct bitcoin_tx *tx;

	tx = tx_spending_utxos(ctx, utxomap, bip32_base, change_satoshis != 0, 0);

	tx->output[0].amount = funding_satoshis;
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	tal_free(wscript);

	if (change_satoshis != 0) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
		tx->output[1].amount = change_satoshis;
		permute_outputs(tx->output, NULL, map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx->input, (const void **)utxomap);
	return tx;
}

struct bitcoin_tx *rgb_funding_tx(const tal_t *ctx,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      u64 funding_satoshis,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      u64 change_satoshis,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base,
			      const struct sha256 asset_id,
			      u32 rgb_amount,
			      u32 rgb_change,
			      const struct rgb_proof *input_proof,
			      struct rgb_proof **funding_proof)
{
    u8 *wscript;
    struct bitcoin_tx *tx;

    tx = tx_spending_utxos(ctx, utxomap, bip32_base, change_satoshis != 0, 1);

    tx->output[0].amount = funding_satoshis;
    wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
    SUPERVERBOSE("# funding witness script = %s\n",
		 tal_hex(wscript, wscript));
    tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
    tal_free(wscript);

    if (change_satoshis != 0) {
	//const void *map[2];
	//map[0] = int2ptr(0);
	//map[1] = int2ptr(1);
	tx->output[1].script = scriptpubkey_p2wpkh(tx, changekey);
	tx->output[1].amount = change_satoshis;
	//permute_outputs(tx->output, NULL, map);
	//*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	*outnum = 0;
    } else {
	*outnum = 0;
    }

    // FIXME: Disabling the permutation right now, it might mess-up RGB commitments
    // permute_inputs(tx->input, (const void **)utxomap);

    struct rgb_proof *proof = tal(ctx, struct rgb_proof);
    proof->contract = NULL;

    proof->bind_to_count = tal_count(utxomap);
    proof->bind_to = tal_arr(ctx, struct rgb_bitcoin_outpoint, proof->bind_to_count);

    for (size_t i = 0; i < proof->bind_to_count; i++) {
        memcpy(&proof->bind_to[i].txid, &utxomap[i]->txid, 32);
        proof->bind_to[i].vout = utxomap[i]->outnum;
    }

    proof->input_count = 1;
    proof->input = (struct rgb_proof*) input_proof;

    proof->output_count = rgb_change ? 2 : 1;
    proof->output = tal_arr(ctx, struct rgb_output_entry, proof->output_count);

    memcpy(&proof->output[0].asset_id, &asset_id, 32);
    proof->output[0].amount = rgb_amount;
    proof->output[0].vout = 0;

    if (rgb_change) {
	memcpy(&proof->output[1].asset_id, &asset_id, 32);
	proof->output[1].amount = rgb_change;
	proof->output[1].vout = 1;
    }

    struct rgb_allocated_array_uint8_t commitment_script = rgb_proof_get_expected_script(proof);
    u8 *tal_script = tal_arr(ctx, u8, commitment_script.size);
    memcpy(tal_script, commitment_script.ptr, commitment_script.size);

    size_t commitment_output = change_satoshis != 0 ? 2 : 1;
    tx->output[commitment_output].amount = 0;
    tx->output[commitment_output].script = tal_script;

    *funding_proof = proof;

    return tx;
}
