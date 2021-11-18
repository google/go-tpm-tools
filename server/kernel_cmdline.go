package server

// See
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/ctype.h
// and
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/ctype.c
func isspace(ch byte) bool {
	// Row 8 - 15
	if ch >= 9 && ch <= 13 {
		return true
	} else if ch == 32 {
		return true
	} else if ch == 160 {
		return true
	}
	return false
}

func skipSpaces(str []byte) []byte {
	i := 0
	for i < len(str) && isspace(str[i]) {
		i++
	}
	return str[i:]
}

// This function should replicate the exact behavior of `next_arg` in
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/cmdline.c
// nextArg takes in a command line and returns the next space-separated argument
// in the line. It ignores spaces enclosed in quotes.
// nextArg returns the param and value, if the argument has an '='. It then returns
// the remaining command line to run nextArg on.
//
// Note:
// - nextArg *mutates* args. Make a copy prior to using this function.
// - args *must* be null-terminated (e.g., the final byte is 0x00).
// - args cannot be the C-style empty string (e.g., {0x00}) or empty byte slice.
// - Consider using parseArgs instead as it does not have these limitations.
func nextArg(args []byte) (param []byte, val []byte, remaining []byte) {
	var i uint
	var equals uint
	inQuote := false
	quoted := false

	if args[0] == '"' {
		args = args[1:]
		inQuote = true
		quoted = true
	}

	for i = 0; len(args) > int(i) && args[i] != 0; i++ {
		if isspace(args[i]) && !inQuote {
			break
		}
		if equals == 0 {
			if args[i] == '=' {
				equals = i
			}
		}
		if args[i] == '"' {
			inQuote = !inQuote
		}
	}

	param = args[:i]
	if equals == 0 {
		val = nil
	} else {
		args[equals] = 0
		param = param[:equals]
		val = args[equals+1 : i]

		/* Don't include quotes in value. */
		if val[0] == '"' {
			val = val[1:]
			if args[i-1] == '"' {
				args[i-1] = 0
				val = val[:len(val)-1]
			}
		}
	}

	if quoted && i > 0 && args[i-1] == '"' {
		args[i-1] = 0
		// Since we don't know whether args[i-1] is in param or val, we
		// use equals to differentiate.
		if equals == 0 {
			param = param[:len(param)-1]
		} else {
			val = val[:len(val)-1]
		}
	}

	if args[i] != 0 {
		args[i] = 0
		if int(i) < len(args)-1 {
			args = args[i+1:]
		}
	} else {
		args = args[i:]
	}

	/* Chew up trailing spaces. */
	return param, val, skipSpaces(args)
}

// parseArgs takes a Linux kernel command line and returns a key value mapping
// for each command line argument.
func parseArgs(commandline []byte) map[string]string {
	var args []byte
	// nextArgs must receive a null-terminated string.
	if len(commandline) == 0 || commandline[len(commandline)-1] != 0 {
		args = make([]byte, len(commandline)+1)
		args[len(args)-1] = 0
	} else {
		args = make([]byte, len(commandline))
	}
	copy(args, commandline)

	var param, val []byte
	paramsToVals := make(map[string]string)

	args = skipSpaces(args)
	for len(args) != 0 && args[0] != 0 {
		param, val, args = nextArg(args)
		paramsToVals[string(param)] = string(val)
	}

	return paramsToVals
}
