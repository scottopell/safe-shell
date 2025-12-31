#!/usr/bin/env escript
%% BEAM VM Runtime Compatibility Test for Landlock Sandbox
%% Tests lightweight processes, message passing, ETS, ports, and system interactions

-mode(compile).

main(_Args) ->
    io:format("~s~n", [string:copies("=", 71)]),
    io:format("BEAM VM Runtime Compatibility Test~n"),
    io:format("Erlang/OTP: ~s~n", [erlang:system_info(otp_release)]),
    io:format("ERTS: ~s~n", [erlang:system_info(version)]),
    io:format("Arch: ~s~n", [erlang:system_info(system_architecture)]),
    io:format("~s~n", [string:copies("=", 71)]),

    Results = #{allowed => [], blocked => [], errors => []},

    %% Run all test sections
    R1 = test_section("Basic Interpreter", fun test_basic/1, Results),
    R2 = test_section("Lightweight Processes", fun test_processes/1, R1),
    R3 = test_section("Message Passing", fun test_messaging/1, R2),
    R4 = test_section("ETS Tables", fun test_ets/1, R3),
    R5 = test_section("Filesystem Operations", fun test_filesystem/1, R4),
    R6 = test_section("Port Programs", fun test_ports/1, R5),
    R7 = test_section("Network Operations", fun test_network/1, R6),
    R8 = test_section("System Info", fun test_system/1, R7),
    R9 = test_section("Memory Operations", fun test_memory/1, R8),

    print_summary(R9),

    %% Exit with error count
    ErrorCount = length(maps:get(errors, R9)),
    halt(ErrorCount).

test_section(Name, Fun, Results) ->
    io:format("~n[SECTION: ~s]~n", [Name]),
    Fun(Results).

test(Name, Fun, ExpectBlock, Results) ->
    Padded = string:pad(Name, 45, trailing),
    io:format("  [TEST] ~s ", [Padded]),
    try
        Fun(),
        io:format("[ALLOWED]~n"),
        add_result(allowed, Name, "", Results)
    catch
        Type:Error ->
            Msg = format_error(Type, Error),
            case ExpectBlock of
                true ->
                    io:format("[BLOCKED] ~s~n", [truncate(Msg, 40)]),
                    add_result(blocked, Name, Msg, Results);
                false ->
                    io:format("[ERROR]   ~s~n", [truncate(Msg, 40)]),
                    add_result(errors, Name, Msg, Results)
            end
    end.

add_result(Category, Name, Details, Results) ->
    Current = maps:get(Category, Results),
    maps:put(Category, [{Name, Details} | Current], Results).

format_error(error, {Reason, _Stack}) -> atom_to_list(Reason);
format_error(error, Reason) when is_atom(Reason) -> atom_to_list(Reason);
format_error(throw, Reason) -> io_lib:format("~p", [Reason]);
format_error(exit, Reason) -> io_lib:format("exit:~p", [Reason]);
format_error(_, Reason) -> io_lib:format("~p", [Reason]).

truncate(Str, Max) ->
    Flat = lists:flatten(Str),
    case length(Flat) > Max of
        true -> string:slice(Flat, 0, Max) ++ "...";
        false -> Flat
    end.

%% ============================================================
%% SECTION 1: Basic Interpreter
%% ============================================================
test_basic(R) ->
    R1 = test("Hello world", fun() ->
        "Hello from BEAM!" = "Hello from BEAM!",
        ok
    end, false, R),

    R2 = test("Math operations", fun() ->
        X = math:sin(1.5) + math:cos(2.5) * math:sqrt(100),
        true = is_float(X),
        ok
    end, false, R1),

    R3 = test("List operations", fun() ->
        L = [1, 2, 3, 4, 5],
        15 = lists:sum(L),
        ok
    end, false, R2),

    R4 = test("Map operations", fun() ->
        M = #{a => 1, b => 2, c => 3},
        1 = maps:get(a, M),
        ok
    end, false, R3),

    R5 = test("Binary operations", fun() ->
        B = <<"Hello BEAM">>,
        10 = byte_size(B),
        ok
    end, false, R4),

    R5.

%% ============================================================
%% SECTION 2: Lightweight Processes
%% ============================================================
test_processes(R) ->
    R1 = test("Spawn process", fun() ->
        Pid = spawn(fun() -> ok end),
        true = is_pid(Pid),
        ok
    end, false, R),

    R2 = test("Spawn 1000 processes", fun() ->
        Pids = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 1000)],
        1000 = length(Pids),
        [Pid ! stop || Pid <- Pids],
        ok
    end, false, R1),

    R3 = test("Spawn 10000 processes", fun() ->
        Pids = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 10000)],
        10000 = length(Pids),
        [Pid ! stop || Pid <- Pids],
        ok
    end, false, R2),

    R4 = test("Process linking", fun() ->
        Parent = self(),
        Pid = spawn_link(fun() -> Parent ! done end),
        receive done -> ok after 1000 -> error(timeout) end,
        ok
    end, false, R3),

    R5 = test("Process monitoring", fun() ->
        {Pid, Ref} = spawn_monitor(fun() -> ok end),
        receive
            {'DOWN', Ref, process, Pid, normal} -> ok
        after 1000 -> error(timeout)
        end
    end, false, R4),

    R5.

%% ============================================================
%% SECTION 3: Message Passing
%% ============================================================
test_messaging(R) ->
    R1 = test("Send/receive message", fun() ->
        Self = self(),
        spawn(fun() -> Self ! {hello, 42} end),
        receive {hello, 42} -> ok after 1000 -> error(timeout) end
    end, false, R),

    R2 = test("Selective receive", fun() ->
        Self = self(),
        spawn(fun() -> Self ! a, Self ! b, Self ! c end),
        receive b -> ok after 1000 -> error(timeout) end,
        receive a -> ok after 1000 -> error(timeout) end,
        receive c -> ok after 1000 -> error(timeout) end
    end, false, R1),

    R3 = test("Message passing chain (100 procs)", fun() ->
        Last = self(),
        Chain = lists:foldl(
            fun(_, Next) ->
                spawn(fun() -> receive Msg -> Next ! Msg end end)
            end,
            Last,
            lists:seq(1, 100)
        ),
        Chain ! {chain_complete, 123},
        receive {chain_complete, 123} -> ok after 5000 -> error(timeout) end
    end, false, R2),

    R3.

%% ============================================================
%% SECTION 4: ETS Tables
%% ============================================================
test_ets(R) ->
    R1 = test("Create ETS table", fun() ->
        Tab = ets:new(test_table, [set, public]),
        true = is_reference(Tab),
        ets:delete(Tab),
        ok
    end, false, R),

    R2 = test("ETS insert/lookup", fun() ->
        Tab = ets:new(test_table, [set]),
        true = ets:insert(Tab, {key, value}),
        [{key, value}] = ets:lookup(Tab, key),
        ets:delete(Tab),
        ok
    end, false, R1),

    R3 = test("ETS 100k entries", fun() ->
        Tab = ets:new(test_table, [set]),
        [ets:insert(Tab, {I, I * 2}) || I <- lists:seq(1, 100000)],
        [{50000, 100000}] = ets:lookup(Tab, 50000),
        ets:delete(Tab),
        ok
    end, false, R2),

    R4 = test("ETS ordered_set", fun() ->
        Tab = ets:new(test_table, [ordered_set]),
        [ets:insert(Tab, {I, I}) || I <- [3, 1, 4, 1, 5, 9, 2, 6]],
        Keys = [K || {K, _} <- ets:tab2list(Tab)],
        [1, 2, 3, 4, 5, 6, 9] = Keys,
        ets:delete(Tab),
        ok
    end, false, R3),

    R4.

%% ============================================================
%% SECTION 5: Filesystem Operations
%% ============================================================
test_filesystem(R) ->
    R1 = test("Read file (/etc/hostname)", fun() ->
        {ok, Content} = file:read_file("/etc/hostname"),
        true = byte_size(Content) > 0,
        ok
    end, false, R),

    R2 = test("List directory (/etc)", fun() ->
        {ok, Files} = file:list_dir("/etc"),
        true = length(Files) > 0,
        ok
    end, false, R1),

    R3 = test("File info", fun() ->
        {ok, Info} = file:read_file_info("/etc/passwd"),
        regular = element(3, Info),
        ok
    end, false, R2),

    R4 = test("Write to /tmp", fun() ->
        Path = "/tmp/beam_test.txt",
        ok = file:write_file(Path, <<"test">>),
        ok = file:delete(Path)
    end, true, R3),

    R5 = test("Write to /dev/shm", fun() ->
        Path = "/dev/shm/beam_test_" ++ integer_to_list(erlang:unique_integer([positive])) ++ ".txt",
        ok = file:write_file(Path, <<"test from beam">>),
        {ok, <<"test from beam">>} = file:read_file(Path),
        ok = file:delete(Path)
    end, false, R4),

    R6 = test("Create directory in /dev/shm", fun() ->
        Path = "/dev/shm/beam_test_dir_" ++ integer_to_list(erlang:unique_integer([positive])),
        ok = file:make_dir(Path),
        ok = file:del_dir(Path)
    end, true, R5),

    R6.

%% ============================================================
%% SECTION 6: Port Programs
%% ============================================================
test_ports(R) ->
    R1 = test("Open port (echo)", fun() ->
        Port = open_port({spawn, "echo hello"}, [stream, exit_status]),
        receive
            {Port, {data, Data}} ->
                "hello\n" = Data,
                ok;
            {Port, {exit_status, 0}} ->
                ok
        after 5000 -> error(timeout)
        end,
        %% Drain remaining messages
        receive {Port, _} -> ok after 100 -> ok end,
        ok
    end, false, R),

    R2 = test("Port with stdin", fun() ->
        Port = open_port({spawn, "cat"}, [stream, exit_status, {line, 1024}]),
        port_command(Port, "test input\n"),
        port_close(Port),
        ok
    end, false, R1),

    R3 = test("os:cmd/1", fun() ->
        Result = os:cmd("echo test"),
        "test\n" = Result,
        ok
    end, false, R2),

    R4 = test("os:getenv/1", fun() ->
        Path = os:getenv("PATH"),
        true = is_list(Path),
        true = length(Path) > 0,
        ok
    end, false, R3),

    R4.

%% ============================================================
%% SECTION 7: Network Operations
%% ============================================================
test_network(R) ->
    R1 = test("TCP connect", fun() ->
        case gen_tcp:connect("127.0.0.1", 80, [], 1000) of
            {ok, Socket} ->
                gen_tcp:close(Socket),
                ok;
            {error, _Reason} ->
                throw(connection_failed)
        end
    end, true, R),

    R2 = test("TCP listen", fun() ->
        case gen_tcp:listen(0, [{reuseaddr, true}]) of
            {ok, Socket} ->
                gen_tcp:close(Socket),
                ok;
            {error, Reason} ->
                throw(Reason)
        end
    end, true, R1),

    R3 = test("UDP socket", fun() ->
        case gen_udp:open(0) of
            {ok, Socket} ->
                gen_udp:close(Socket),
                ok;
            {error, Reason} ->
                throw(Reason)
        end
    end, true, R2),

    R4 = test("inet:gethostname/0", fun() ->
        {ok, Hostname} = inet:gethostname(),
        true = is_list(Hostname),
        ok
    end, false, R3),

    R4.

%% ============================================================
%% SECTION 8: System Info
%% ============================================================
test_system(R) ->
    R1 = test("erlang:system_info/1", fun() ->
        Procs = erlang:system_info(process_count),
        true = Procs > 0,
        ok
    end, false, R),

    R2 = test("erlang:memory/0", fun() ->
        Mem = erlang:memory(),
        Total = proplists:get_value(total, Mem),
        true = Total > 0,
        ok
    end, false, R1),

    R3 = test("os:type/0", fun() ->
        {unix, linux} = os:type(),
        ok
    end, false, R2),

    R4 = test("os:timestamp/0", fun() ->
        {MegaSecs, Secs, MicroSecs} = os:timestamp(),
        true = MegaSecs >= 0,
        true = Secs >= 0,
        true = MicroSecs >= 0,
        ok
    end, false, R3),

    R4.

%% ============================================================
%% SECTION 9: Memory Operations
%% ============================================================
test_memory(R) ->
    R1 = test("Large list (1M elements)", fun() ->
        L = lists:seq(1, 1000000),
        1000000 = length(L),
        ok
    end, false, R),

    R2 = test("Large binary (10MB)", fun() ->
        B = binary:copy(<<0>>, 10 * 1024 * 1024),
        10485760 = byte_size(B),
        ok
    end, false, R1),

    R3 = test("Binary allocation (50MB)", fun() ->
        B = binary:copy(<<0>>, 50 * 1024 * 1024),
        52428800 = byte_size(B),
        ok
    end, false, R2),

    R4 = test("Garbage collection", fun() ->
        %% Create and discard large data to trigger GC
        _ = [lists:seq(1, 10000) || _ <- lists:seq(1, 100)],
        erlang:garbage_collect(),
        ok
    end, false, R3),

    R4.

%% ============================================================
%% Summary
%% ============================================================
print_summary(Results) ->
    Allowed = lists:reverse(maps:get(allowed, Results)),
    Blocked = lists:reverse(maps:get(blocked, Results)),
    Errors = lists:reverse(maps:get(errors, Results)),

    io:format("~n~s~n", [string:copies("=", 71)]),
    io:format("SUMMARY~n"),
    io:format("~s~n", [string:copies("=", 71)]),
    io:format("  Allowed:  ~p tests~n", [length(Allowed)]),
    io:format("  Blocked:  ~p tests (expected)~n", [length(Blocked)]),
    io:format("  Errors:   ~p tests (unexpected)~n", [length(Errors)]),
    io:format("~s~n", [string:copies("=", 71)]),

    case Errors of
        [] -> ok;
        _ ->
            io:format("~nUNEXPECTED ERRORS:~n"),
            [io:format("  - ~s: ~s~n", [N, D]) || {N, D} <- Errors]
    end,

    io:format("~nALLOWED OPERATIONS:~n"),
    [io:format("  [+] ~s~n", [N]) || {N, _} <- Allowed],

    io:format("~nBLOCKED OPERATIONS (as expected):~n"),
    [io:format("  [-] ~s: ~s~n", [N, D]) || {N, D} <- Blocked],

    ok.
