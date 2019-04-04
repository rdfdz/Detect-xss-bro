
# Match HTML Codes
const match_entities = /&#[0-9]+;?/
    | /&#[x][0-9a-f]+;?/;

const match_code = /[0-9a-f]+/;

# Match HTML Codes
const match_html_names =  /&[a-z]+;/;

# HTML Names Table
global html_name: table[string] of string = {

    ["&lt;"] = "<", ["&gt;"] = ">", ["&amp;"] = "&", ["&quot;"] = "\"",
    ["&apos;"] = "'", ["&colon;"] = ":", 
};

# HTML Codes Table
global html_code: table[int] of string = {
    [33] = "!", [34] = "\"",[35] = "#", [36] = "$", [37] = "%", [38] = "&",
    [39] = "'", [40] = "(", [41] = ")", [42] = "*", [43] = "+", [44] = ",",
    [45] = "-", [46] = ".", [47] = "/", [48] = "0", [49] = "1", [50] = "2",
    [51] = "3", [52] = "4", [53] = "5", [54] = "6", [55] = "7", [56] = "8",
    [57] = "9", [58] = ":", [59] = ";", [60] = "<", [61] = "=", [62] = ">",
    [63] = "?", [64] = "@", [65] = "A", [66] = "B", [67] = "C", [68] = "D",
    [69] = "E", [70] = "F", [71] = "G", [72] = "H", [73] = "I", [74] = "J",
    [75] = "K", [76] = "L", [77] = "M", [78] = "N", [79] = "O", [80] = "P",
    [81] = "Q", [82] = "R", [83] = "S", [84] = "T", [85] = "U", [86] = "V",
    [87] = "W", [88] = "X", [89] = "Y", [90] = "Z", [91] = "[", [92] = "\\",
    [93] = "]", [94] = "^", [95] = "_", [96] = "`", [97] = "a", [98] = "b",
    [99] = "c", [100] = "d", [101] = "e", [102] = "f", [103] = "g", [104] = "h",
    [105] = "i", [106] = "j", [107] = "k",[108] = "l", [109] = "m", [110] = "n",
    [111] = "o", [112] = "p", [113] = "q",[114] = "r", [115] = "s", [116] = "t",
    [117] = "u", [118] = "v", [119] = "W",[120] = "x", [121] = "y", [122] = "z",
    [123] = "{", [124] = "|", [125] = "}",[126] = "~",
};

# Function to decode ASCII html names
function decode_html_names(payload: string): string {

    local find = find_all(payload, match_html_names);

    for (name in find) {

        if (name in html_name) {

            payload =  subst_string(payload, name, html_name[name]);
        }
    }

    return payload;
}


# Function to decode ASCII characters
function decode(payload: string): string {

    local find = match_pattern(payload, match_entities);
    local code: int;

    if (find$str[2] == "x") {

        local hex = match_pattern(find$str,match_code)$str;

        if ( |hex| % 2 != 0) {
            hex = "0" + hex;
        }

        local hexstring = hexstr_to_bytestring(hex);
        local clean_hex = gsub(hexstring, /\x00/, "");
        code = bytestring_to_count(clean_hex);

    } else {

        code = to_int(match_pattern(find$str,match_code)$str);
    }

    if (find$matched == T && (code in html_code)) {

        return decode(sub(payload, match_entities, html_code[code]));
    }

    return payload;
}


# Funtion to clean expression comment
function xss_expression_comment(payload: string): string {

	return gsub(payload, /\/\*.+?\*\//, "");
}


# Steps to sanitize
function sanitize(unescaped_URI: string) : string{

    # Case insensitive
    local ins = to_lower(unescaped_URI);

    # Decode HTML names
    ins = decode_html_names(ins);

    # Clean expression
    ins = xss_expression_comment(ins);

    # Decode HTML code
    return decode(ins);
}
