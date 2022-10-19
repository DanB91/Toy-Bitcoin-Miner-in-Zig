//f(k, n) < t
//
//k -> the block header excluding the nonce
//n -> nonce
//t -> target
//f -> mining algorithm -- sha256(sha256(concat(k, n)))

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const BigInt = std.math.big.int.Mutable;
const Thread = std.Thread;
const print = std.debug.print;
const milliTimestamp = std.time.milliTimestamp;

const current_block: [80]u8 =
    b: {
    var block: [80]u8 = undefined;

    var version = 0x20000000;
    var prev_block_hash = 0x00000000000000000000961de6996f15a68ab1b9f96c45b51be7b4b691354bf4;
    var merkle_root = 0x8c5df2435393a63067bc22c963fb1ca6f75c8a3eb669ac94f742c58756530a48;
    var time = 1618240510;
    var bits = 0x170c2a48;
    for (block[0..4]) |*dest| {
        dest.* = @truncate(u8, version & 0xFF);
        version >>= 8;
    }
    for (block[4..36]) |*dest| {
        dest.* = @truncate(u8, prev_block_hash & 0xFF);
        prev_block_hash >>= 8;
    }

    for (block[36..68]) |*dest| {
        dest.* = @truncate(u8, merkle_root & 0xFF);
        merkle_root >>= 8;
    }

    for (block[68..72]) |*dest| {
        dest.* = @truncate(u8, time & 0xFF);
        time >>= 8;
    }

    for (block[72..76]) |*dest| {
        dest.* = @truncate(u8, bits & 0xFF);
        bits >>= 8;
    }

    //nonce
    for (block[76..80]) |*dest| {
        dest.* = 0;
    }

    break :b block;
};

const MiningState = struct {
    //modified by mining thread
    nonce: u32,
    nonce_limit: u32,
    num_hashes: usize,
    total_time_ms: i64,
    max_time_ms: i64,
    min_time_ms: i64,
    thread: Thread,
    result: ?u32,
};

fn mining_thread(mining_state: *MiningState) void {
    while (g_is_running) {
        const start = milliTimestamp();
        const mined_block = did_we_mine_a_block(mining_state.nonce, g_target);
        const end = milliTimestamp();
        mining_state.total_time_ms += end - start;
        if (end - start > mining_state.max_time_ms) mining_state.max_time_ms = end - start;
        if (end - start < mining_state.min_time_ms) mining_state.min_time_ms = end - start;
        mining_state.num_hashes += 1;
        if (mined_block) {
            mining_state.result = mining_state.nonce;
            g_is_running = false;
            return;
        }
        if (mining_state.nonce >= mining_state.nonce_limit) {
            return;
        }
        mining_state.nonce += 1;
    }
    return;
}
var mining_states: struct {
    buffer: [32]MiningState,
    states: []MiningState,
} = .{
    .buffer = undefined,
    .states = &[0]MiningState{},
};
var g_is_running = true;
var g_start_ms: i64 = 0;

var g_target: [32]u8 = undefined;
pub fn main() !void {
    g_target = bits_to_target(current_block[72 .. 72 + 4]);
    {
        var i: usize = 0;
        const num_cores = try Thread.getCpuCount();
        print("Running on {} cores\n", .{num_cores});
        const increment: u32 = 0xFFFF_FFFF / @intCast(u32, num_cores);
        var nonce_start: u32 = 0;
        while (i < num_cores) : (i += 1) {
            mining_states.buffer[i] = MiningState{
                .nonce = nonce_start,
                .nonce_limit = nonce_start + increment,
                .num_hashes = 0,
                .total_time_ms = 0,
                .max_time_ms = 0,
                .min_time_ms = 0x7FFF_FFFF_FFFF_FFFF,
                .thread = undefined,
                .result = null,
            };
            var mining_state = &mining_states.buffer[i];
            mining_state.thread = try Thread.spawn(.{}, mining_thread, .{mining_state});
            nonce_start += increment;
        }

        mining_states.states = mining_states.buffer[0..num_cores];
    }
    g_start_ms = milliTimestamp();

    for (mining_states.states) |*mining_state| {
        mining_state.thread.join();
    }

    print("Time elapsed: {d} seconds\n", .{ms_to_sec(milliTimestamp() - g_start_ms)});
    for (mining_states.states) |*mining_state, i| {
        if (mining_state.result) |result| {
            print("Result {X} found in miner {}\n", .{ result, i });
        }
    }

    for (mining_states.states) |*mining_state, i| {
        print("btc miner {}\n", .{i});
        if (mining_state.result) |result| {
            print("result: {X}\n", .{result});
        } else {
            print("result: null\n", .{});
        }
        print("num hashes: {}\n", .{mining_state.num_hashes});
        print("total time: {}ms\n", .{mining_state.total_time_ms});
        print("max time: {}ms\n", .{mining_state.max_time_ms});
        print("min time: {}ms\n", .{mining_state.min_time_ms});
        print("avg time per hash: {d:.2}ms\n", .{if (mining_state.total_time_ms > 0) @intToFloat(f64, mining_state.total_time_ms) / @intToFloat(f64, mining_state.num_hashes) else 0});
        print("\n", .{});
    }
}
fn ms_to_sec(ms: i64) f64 {
    return @intToFloat(f64, ms) / 1_000.0;
}

fn bits_to_target(bits: []const u8) [32]u8 {
    var ret: [32]u8 = undefined;
    var target_limb_buffer: [66]usize = undefined;

    const coefficient = @as(u32, bits[0]) + (@as(u32, bits[1]) << 8) +
        (@as(u32, bits[2]) << 16);

    var scratch_limbs: [66]usize = undefined;

    var base_limb_buffer: [1]usize = undefined;
    var tmp = BigInt.init(&base_limb_buffer, 2);
    var target = BigInt.init(&target_limb_buffer, 0);
    target.pow(tmp.toConst(), 8 * (@as(u32, bits[3]) - 3), &scratch_limbs) catch |e| {
        print("Error computing target: {}", .{e});
        return ret;
    };
    tmp.set(coefficient);
    target.mul(target.toConst(), tmp.toConst(), &scratch_limbs, null);

    {
        var byte_index: u6 = 0;
        var limb_index: usize = 0;
        for (ret) |*dest| {
            dest.* = @truncate(u8, (target_limb_buffer[limb_index] >> (byte_index * 8)) & 0xFF);
            byte_index += 1;
            if (byte_index >= 8) {
                limb_index += 1;
                byte_index = 0;
            }
        }
    }

    return ret;
}

fn did_we_mine_a_block(nonce: u32, target: [32]u8) bool {
    var block_header = current_block;
    {
        comptime var ci = 0;
        inline while (ci < 4) : (ci += 1) {
            block_header[ci + 76] = @intCast(u8, (nonce >> (ci * 8)) & 0xFF);
        }
    }
    var hash_result: [32]u8 = undefined;
    var tmp_result: [32]u8 = undefined;

    Sha256.hash(&block_header, &tmp_result, .{});
    Sha256.hash(&tmp_result, &hash_result, .{});

    comptime var i = @as(comptime_int, target.len) - 1;
    inline while (i >= 0) : (i -= 1) {
        if (hash_result[i] < target[i]) {
            //BIG MONEY!!!
            return true;
        } else if (hash_result[i] > target[i]) {
            //no money :(
            return false;
        }
    }

    return false;
}
