#!/usr/bin/env julia
import Sockets
import DataStructures
import Printf

using ArgParse

START_PORT = 1
END_PORT = 1001

CLOSED_MSG = "ECONNREFUSED"
RESET_MSG = "ECONNRESET"

function parse_arguments()
    s = ArgParseSettings()
    @add_arg_table! s begin
        "--target", "-t"
        help = "ip address of target machine"
        arg_type = String
        required = true
        "--start", "-s"
        help = "Start port. Default 1."
        arg_type = Int
        default = 1
        "--end", "-e"
        help = "End port. Default 1001."
        arg_type = Int
        default = 1001
        "--open", "-o"
        help = "Show open ports only. Default false."
        action = :store_true
    end
    return parse_args(s)
end

function print_results(output, only_open)
    for (key, value) in output
        if only_open && value != "OPEN"
            continue
        end
        Printf.@printf("Port %5d - %s\n", key, value)
    end
end

function scan()
    parsed_args = parse_arguments()
    target = get(parsed_args, "target", "")
    if target == ""
        print("\nNo ip target was informed!")
        exit(1)
    end
    start = coalesce(get(parsed_args, "start", missing), START_PORT)
    finish = coalesce(get(parsed_args, "end", missing), END_PORT)
    only_open = coalesce(get(parsed_args, "open", missing), false)
    ports = DataStructures.OrderedDict{Int64,String}()
    open_count = 0
    closed_count = 0
    filtered_count = 0
    print("Running port scanning for $target\n\n")
    start_time = time()
    for port = start:finish
        try
            socket = Sockets.connect(target, port)
            push!(ports, port => "OPEN")
            open_count += 1
            close(socket)
        catch e
            if isa(e, Base.IOError)
                # Closed port
                if occursin(CLOSED_MSG, e.msg)
                    push!(ports, port => "CLOSED")
                    closed_count += 1
                end
                # Filtered port
                if occursin(RESET_MSG, e.msg)
                    push!(ports, port => "FILTERED")
                    filtered_count += 1
                end
            end
        end
    end
    elapsed_time = time() - start_time
    print("TCP port scanning complete!\n")
    print("$open_count open ports, $closed_count closed and $filtered_count filtered\n")
    print_results(ports, only_open)
    print("\nFinished in $elapsed_time seconds")
end

# Start scanning
scan()
