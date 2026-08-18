import Foundation

/// The words people actually reach for when asked to invent a passphrase.
///
/// Hand-authored from the shape every published breach corpus shares — the
/// classic top passwords, first names, sports and brands, the calendar, the
/// keyboard, the vocabulary of this app's own subject matter, and the
/// pinyin-and-digits family that dominates Chinese-language lists. It is
/// deliberately a few hundred entries rather than a few hundred thousand: it
/// covers the head of the distribution, which is where guessing actually
/// succeeds, and it ships as source rather than as vendored data, so it carries
/// no licence of its own and needs no download.
///
/// Order is the ranking. Earlier entries are the more common guesses, and
/// `PassphraseStrengthEstimator` charges a match `log2(rank)` bits, so matching
/// `password` costs almost nothing while matching `trezor` costs a byte's worth.
enum CommonPassphraseTokens {
    /// Shortest token the estimator will match. Latin entries are kept longer
    /// than this — the repeat and sequence matchers already cover the
    /// degenerate cases, and short letter tokens start cheapening random text
    /// by coincidence — but three ideographs are already a whole phrase.
    static let minimumLength = 3

    static let ordered: [String] = [
        // The head of every leaked-password list.
        "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
        "111111", "000000", "123123", "abc123", "letmein", "iloveyou", "admin",
        "welcome", "monkey", "dragon", "sunshine", "princess", "football",
        "baseball", "master", "shadow", "superman", "trustno1", "batman",
        "passw0rd", "654321", "666666", "888888", "121212", "112233", "789456",
        "987654321", "qazwsx", "qwertyuiop", "asdfgh", "zxcvbnm", "1qaz2wsx",
        "zaq12wsx", "1q2w3e4r", "qwer1234", "asdf1234", "mnbvcxz", "poiuytrewq",

        // First names and pet names.
        "michael", "jennifer", "jessica", "ashley", "michelle", "amanda",
        "samantha", "nicole", "hannah", "jasmine", "charlie", "daniel",
        "thomas", "robert", "joshua", "matthew", "andrew", "anthony",
        "william", "richard", "george", "jordan", "hunter", "harley",
        "ranger", "buster", "tigger", "mickey", "pepper", "cookie",

        // Everyday nouns.
        "chocolate", "flower", "butterfly", "rainbow", "purple", "orange",
        "yellow", "silver", "golden", "diamond", "phoenix", "ninja",
        "samurai", "warrior", "killer", "hello", "freedom", "whatever",
        "secret", "angel", "lovely", "sweetie", "babygirl", "cheese",
        "banana", "coffee", "summer", "winter", "autumn", "spring",
        "monster", "shadowfax", "unicorn", "kitten", "puppy", "panda",

        // Sport and machinery.
        "basketball", "soccer", "hockey", "tennis", "chelsea", "liverpool",
        "arsenal", "barcelona", "madrid", "ferrari", "porsche", "mustang",
        "yamaha", "honda", "toyota", "corvette", "harleydavidson",

        // Computers and brands.
        "computer", "internet", "matrix", "oracle", "server", "system",
        "default", "guest", "test", "demo", "sample", "temp", "changeme",
        "access", "login", "root", "user", "administrator", "samsung",
        "google", "apple", "iphone", "android", "microsoft", "windows",
        "linux", "ubuntu", "amazon", "facebook", "instagram", "twitter",
        "snapchat", "tiktok", "netflix", "spotify", "youtube", "github",
        "gmail", "yahoo", "hotmail", "outlook", "dropbox", "paypal",
        "steam", "minecraft", "fortnite", "pokemon", "starwars", "marvel",
        "disney",

        // The vocabulary of this app — the words a user is looking at when the
        // passphrase field asks them a question.
        "cypherair", "cypher", "openpgp", "gnupg", "encrypt", "decrypt",
        "crypto", "cipher", "keychain", "privatekey", "publickey",
        "passphrase", "security", "secure", "backup", "restore", "recovery",
        "seedphrase", "mnemonic", "bitcoin", "ethereum", "wallet", "satoshi",
        "blockchain", "ledger", "trezor", "signature", "fingerprint",

        // The calendar.
        "january", "february", "march", "april", "june", "july", "august",
        "september", "october", "november", "december", "monday", "tuesday",
        "wednesday", "thursday", "friday", "saturday", "sunday", "birthday",
        "christmas", "halloween", "holiday",

        // Phrases, including the one every security-minded user has read.
        "loveyou", "ihateyou", "fuckyou", "fuckoff", "bullshit", "nothing",
        "forever", "together", "mypassword", "newpassword", "oldpassword",
        "notapassword", "thisisapassword", "secretkey", "changeit",
        "correcthorsebatterystaple", "correct horse battery staple",
        "opensesame", "hunter2",

        // Pinyin, digits, and phrases that lead Chinese-language lists.
        "woaini", "woaini1314", "5201314", "1314520", "520520", "wangyi",
        "taobao", "baidu", "tencent", "weixin", "wechat", "alipay",
        "zhangwei", "wangwei", "lihua", "xiaoming", "liwei", "chenjie",
        "nihao", "zhongguo", "beijing", "shanghai", "guangzhou", "shenzhen",
        "aini", "aiwo", "meinv", "shuaige", "laoban", "gongsi", "mima",
        "shengri", "kuaile", "buzhidao", "meiguanxi", "shenmedou",
        "我爱你", "生日快乐", "一生一世", "永远爱你", "身份证号", "我的密码",
    ]
}
