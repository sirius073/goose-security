-- secgoose.lua
-- Wireshark Lua Dissector for Benchmarked Secured GOOSE

local p_secgoose = Proto("secgoose", "Secured GOOSE Protocol")

-- 1. Define Protocol Fields
local f_bench_ts   = ProtoField.double("secgoose.bench_ts", "Benchmarking Timestamp (8 bytes)", base.DEC)
local f_salt       = ProtoField.bytes("secgoose.salt", "Salt", base.SPACE)
local f_pubkey     = ProtoField.bytes("secgoose.pubkey", "Public Key", base.SPACE)
local f_nonce12    = ProtoField.bytes("secgoose.nonce12", "Nonce (12 Bytes)", base.SPACE)
local f_nonce16    = ProtoField.bytes("secgoose.nonce16", "Nonce (16 Bytes)", base.SPACE)
local f_ciphertext = ProtoField.bytes("secgoose.ciphertext", "Ciphertext", base.SPACE)
local f_sig        = ProtoField.bytes("secgoose.signature", "Signature", base.SPACE)

p_secgoose.fields = { f_bench_ts, f_salt, f_pubkey, f_nonce12, f_nonce16, f_ciphertext, f_sig }

-- 2. User Preferences for Algorithm Selection
local algo_enum = {
    { 0, "None (Plain GOOSE + Timestamp)", 0 },
    { 1, "ASCON-128a", 1 },
    { 2, "AES-256-GCM", 2 },
    { 3, "ChaCha20", 3 },
    { 4, "ECIES", 4 },
    { 5, "Ed25519 (Signed Plaintext)", 5 }
}
p_secgoose.prefs.algo = Pref.enum("Cryptographic Algorithm", 0, "Select the algorithm used to secure the payload", algo_enum)

-- Map for UI display
local algo_names = {
    [0] = "None (Plain GOOSE)",
    [1] = "ASCON-128a",
    [2] = "AES-256-GCM",
    [3] = "ChaCha20",
    [4] = "ECIES",
    [5] = "Ed25519"
}

-- Fetch the Native GOOSE dissector
local goose_dissector = Dissector.get("goose")

-- 3. Main Dissection Logic
function p_secgoose.dissector(buffer, pinfo, tree)
    if buffer:len() < 8 then return end

    local algo = p_secgoose.prefs.algo
    local algo_name = algo_names[algo] or "Unknown"

    pinfo.cols.protocol = "SecGoose"
    pinfo.cols.info:set(algo_name .. " Payload [Len: " .. buffer:len() .. "]")

    -- Create our secure layer tree
    local subtree = tree:add(p_secgoose, buffer(), "Secure GOOSE Layer (" .. algo_name .. ")")
    subtree:add(f_bench_ts, buffer(0, 8))

    -- 4. Parse fields & hand off to native GOOSE if applicable
    if algo == 0 then
        -- No Crypto: Hand to root tree so the normal GOOSE payload expands fully
        if buffer:len() > 8 and goose_dissector then
            goose_dissector:call(buffer(8):tvb(), pinfo, tree)
        end

    elseif algo == 1 then
        if buffer:len() < 56 then return end
        subtree:add(f_salt, buffer(8, 32))
        subtree:add(f_nonce16, buffer(40, 16))
        subtree:add(f_ciphertext, buffer(56))

    elseif algo == 2 or algo == 3 then
        if buffer:len() < 52 then return end
        subtree:add(f_salt, buffer(8, 32))
        subtree:add(f_nonce12, buffer(40, 12))
        subtree:add(f_ciphertext, buffer(52))

    elseif algo == 4 then
        if buffer:len() < 52 then return end
        subtree:add(f_pubkey, buffer(8, 32))
        subtree:add(f_nonce12, buffer(40, 12))
        subtree:add(f_ciphertext, buffer(52))

    elseif algo == 5 then
        if buffer:len() < 88 then return end
        subtree:add(f_nonce16, buffer(8, 16))
        subtree:add(f_sig, buffer(24, 64))
        
        -- Ed25519 is only signed, not encrypted! Hand plaintext to root tree.
        if goose_dissector then
            goose_dissector:call(buffer(88):tvb(), pinfo, tree)
        end
    end
end

-- 5. Register the Dissector
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x88b8, p_secgoose)
