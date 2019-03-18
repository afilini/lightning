#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <common/json_helpers.h>
#include <errno.h>
#include <rgb.h>

static inline uint8_t char_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 0x0A;
    return c - 'A' + 0x0A;
}

static void decode_reverse_hex(const char *c, uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; ++i) {
	buffer[len - i - 1] = (char_value(c[i * 2]) << 4) | char_value(c[i * 2 + 1]);
    }
}

bool json_to_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			    uint64_t *satoshi)
{
	char *end;
	unsigned long btc, sat;

	btc = strtoul(buffer + tok->start, &end, 10);
	if (btc == ULONG_MAX && errno == ERANGE)
		return false;
	if (end != buffer + tok->end) {
		/* Expect always 8 decimal places. */
		if (*end != '.' || buffer + tok->end - end != 9)
			return false;
		sat = strtoul(end+1, &end, 10);
		if (sat == ULONG_MAX && errno == ERANGE)
			return false;
		if (end != buffer + tok->end)
			return false;
	} else
		sat = 0;

	*satoshi = btc * (uint64_t)100000000 + sat;
	if (*satoshi != btc * (uint64_t)100000000 + sat)
		return false;

	return true;
}

bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey)
{
	return pubkey_from_hexstr(buffer + tok->start,
				  tok->end - tok->start, pubkey);
}

bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid,
			      bool may_be_deprecated_form)
{
	return (short_channel_id_from_str(buffer + tok->start,
					  tok->end - tok->start, scid,
					  may_be_deprecated_form));
}

bool json_to_asset_id(const char *buffer, const jsmntok_t *tok,
	              struct rgb_sha256d *asset_id)
{
    if (tok->end - tok->start != 64) {
        return false;
    }

    decode_reverse_hex(buffer + tok->start, (uint8_t*) asset_id, 32);
    return true;
}