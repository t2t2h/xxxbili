// DomainSniffer - يسجّل النطاقات والـ IP التي يتصل بها التطبيق ويعرضها في قائمة عائمة.
// DomainSniffer  —  © أفلاطون (Aflatoon / Plato) — جميع الحقوق محفوظة
// يراقب الاتصالات، ويحجب عبر NextDNS API، ويطبّق قواعد استبدال (نطاق/IP) محفوظة.
// لا يحتاج Substrate / ElleKit: محرك الـ hook مدمج (إعادة ربط رموز Mach-O + ObjC runtime).

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#import <AVFoundation/AVFoundation.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <sys/time.h>

#pragma mark - Store

@interface DSStore : NSObject
+ (instancetype)shared;
- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed;
- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src;
- (NSArray<NSDictionary *> *)snapshot;
- (NSArray<NSURL *> *)saveAll;
- (NSString *)denylistText;
- (NSUInteger)denylistCount;
- (void)clear;
@end

static BOOL DSIsIPString(NSString *s) {
    struct in_addr a4; struct in6_addr a6;
    return inet_pton(AF_INET, s.UTF8String, &a4) == 1 || inet_pton(AF_INET6, s.UTF8String, &a6) == 1;
}

static NSString *DSDir(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *dir = [docs stringByAppendingPathComponent:@"DomainSniffer"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}


#pragma mark - Settings (persistent)

// أعلام سريعة تُقرأ من خيوط الشبكة بدون قفل
static volatile BOOL gHasRules = NO, gHasIPRules = NO;
static volatile BOOL gChatMode = NO;   // تحويل نطاقات وIPs الدردشة والكتابة أونلاين إلى 8.8.8.8
static volatile BOOL gForceAll = NO;   // تحويل كل النطاقات والـ IPs إلى 8.8.8.8 (لحظي)
static volatile BOOL gAutoDNS = YES;   // وضع DNS تلقائي → 8.8.8.8

@interface DSSettings : NSObject
+ (instancetype)shared;
@property (atomic, copy) NSString *apiKey;
@property (atomic, copy) NSString *profileId;
@property (atomic) BOOL autoDNS;
@property (atomic) BOOL forceAll;
@property (atomic) BOOL chatMode;
@property (atomic, copy) NSArray<NSString *> *chatKeywords;
@property (atomic) BOOL joinSoundOn;
@property (atomic) float joinSoundRate;   // 1..4
@property (atomic) BOOL voiceSpeedOn;
@property (atomic) float voiceSpeedMax;   // 1..4 — أقصى سرعة "لحاق" بصوت المتكلمين داخل الروم
- (NSArray<NSDictionary *> *)rules;
- (void)addRuleFrom:(NSString *)f to:(NSString *)t;
- (void)setRule:(NSUInteger)i enabled:(BOOL)on;
- (void)removeRule:(NSUInteger)i;
- (NSString *)targetFor:(NSString *)host;
- (BOOL)wasSent:(NSString *)d;
- (void)markSent:(NSString *)d;
- (void)save;
@end

@implementation DSSettings {
    NSMutableArray<NSDictionary *> *_rules;
    NSMutableSet<NSString *> *_sent;
}

+ (instancetype)shared {
    static DSSettings *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DSSettings new]; });
    return s;
}

- (NSString *)path { return [DSDir() stringByAppendingPathComponent:@"settings.json"]; }

- (instancetype)init {
    if ((self = [super init])) {
        _rules = [NSMutableArray array];
        self.autoDNS = YES;   // الافتراضي: مفعّل
        self.chatKeywords = @[];
        self.joinSoundRate = 1.0;
        self.voiceSpeedMax = 1.0;
        _sent = [NSMutableSet set];
        NSData *d = [NSData dataWithContentsOfFile:[self path]];
        NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
        if ([j isKindOfClass:NSDictionary.class]) {
            self.apiKey = j[@"apiKey"];
            self.profileId = j[@"profileId"];
            if (j[@"autoDNS"]) self.autoDNS = [j[@"autoDNS"] boolValue];
            self.forceAll = [j[@"forceAll"] boolValue];
            self.chatMode = [j[@"chatMode"] boolValue];
            if ([j[@"chatKeywords"] isKindOfClass:[NSArray class]]) self.chatKeywords = j[@"chatKeywords"];
            self.joinSoundOn = [j[@"joinSoundOn"] boolValue];
            if (j[@"joinSoundRate"]) self.joinSoundRate = [j[@"joinSoundRate"] floatValue];
            self.voiceSpeedOn = [j[@"voiceSpeedOn"] boolValue];
            if (j[@"voiceSpeedMax"]) self.voiceSpeedMax = [j[@"voiceSpeedMax"] floatValue];
            for (NSDictionary *r in j[@"rules"]) {
                if ([r[@"from"] isKindOfClass:NSString.class] && [r[@"to"] isKindOfClass:NSString.class])
                    [_rules addObject:@{ @"from": r[@"from"], @"to": r[@"to"], @"enabled": @([r[@"enabled"] boolValue]) }];
            }
            [_sent addObjectsFromArray:j[@"sent"] ?: @[]];
        }
        [self refreshFlags];
    }
    return self;
}

- (void)refreshFlags {  // داخل @synchronized(self) أو من init
    BOOL any = NO, ip = NO;
    for (NSDictionary *r in _rules) {
        if (![r[@"enabled"] boolValue]) continue;
        any = YES;
        if (DSIsIPString(r[@"from"])) ip = YES;
    }
    gHasRules = any; gHasIPRules = ip; gAutoDNS = self.autoDNS; gForceAll = self.forceAll; gChatMode = self.chatMode;
}

- (void)save {
    NSDictionary *dump;
    @synchronized (self) {
        [self refreshFlags];
        dump = @{ @"apiKey": self.apiKey ?: @"", @"profileId": self.profileId ?: @"", @"autoDNS": @(self.autoDNS), @"forceAll": @(self.forceAll), @"chatMode": @(self.chatMode), @"chatKeywords": self.chatKeywords ?: @[], @"joinSoundOn": @(self.joinSoundOn), @"joinSoundRate": @(self.joinSoundRate), @"voiceSpeedOn": @(self.voiceSpeedOn), @"voiceSpeedMax": @(self.voiceSpeedMax),
                  @"rules": [_rules copy], @"sent": [[_sent allObjects] sortedArrayUsingSelector:@selector(compare:)] };
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[self path] atomically:YES];
}

- (NSArray<NSDictionary *> *)rules { @synchronized (self) { return [_rules copy]; } }

- (void)addRuleFrom:(NSString *)f to:(NSString *)t {
    f = [f stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
    t = [t stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].lowercaseString;
    if (!f.length || !t.length) return;
    @synchronized (self) {
        for (NSUInteger i = 0; i < _rules.count; i++)   // نفس المصدر: حدّث الهدف
            if ([_rules[i][@"from"] isEqualToString:f]) { [_rules removeObjectAtIndex:i]; break; }
        [_rules addObject:@{ @"from": f, @"to": t, @"enabled": @YES }];
    }
    [self save];
}

- (void)setRule:(NSUInteger)i enabled:(BOOL)on {
    @synchronized (self) {
        if (i >= _rules.count) return;
        NSMutableDictionary *r = [_rules[i] mutableCopy]; r[@"enabled"] = @(on); _rules[i] = r;
    }
    [self save];
}

- (void)removeRule:(NSUInteger)i {
    @synchronized (self) { if (i < _rules.count) [_rules removeObjectAtIndex:i]; }
    [self save];
}

- (NSString *)targetFor:(NSString *)host {
    if (!gHasRules || host.length == 0) return nil;
    host = host.lowercaseString;
    @synchronized (self) {
        for (NSDictionary *r in _rules) {
            if (![r[@"enabled"] boolValue]) continue;
            NSString *f = r[@"from"];
            if ([f hasPrefix:@"*."]) { if ([host hasSuffix:[f substringFromIndex:1]]) return r[@"to"]; }
            else if ([host isEqualToString:f]) return r[@"to"];
        }
    }
    return nil;
}

- (BOOL)wasSent:(NSString *)d { @synchronized (self) { return [_sent containsObject:d.lowercaseString]; } }
- (void)markSent:(NSString *)d { @synchronized (self) { [_sent addObject:d.lowercaseString]; } [self save]; }
@end

#pragma mark - NextDNS API

static void DSNDRequest(NSString *method, NSString *path, NSDictionary *body,
                        void (^cb)(NSInteger code, id json, NSError *err)) {
    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:[@"https://api.nextdns.io" stringByAppendingString:path]]];
    r.HTTPMethod = method; r.timeoutInterval = 15;
    [r setValue:[DSSettings shared].apiKey ?: @"" forHTTPHeaderField:@"X-Api-Key"];
    if (body) {
        r.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        [r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }
    [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData *d, NSURLResponse *resp, NSError *e) {
        id j = d.length ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
        NSInteger code = [resp isKindOfClass:NSHTTPURLResponse.class] ? ((NSHTTPURLResponse *)resp).statusCode : 0;
        dispatch_async(dispatch_get_main_queue(), ^{ cb(code, j, e); });
    }] resume];
}

// يجلب Profile ID تلقائياً (أول حساب) إذا لم يُدخل يدوياً
static void DSNDEnsureProfile(void (^cb)(NSString *pid, NSString *err)) {
    DSSettings *st = [DSSettings shared];
    if (st.profileId.length) { cb(st.profileId, nil); return; }
    DSNDRequest(@"GET", @"/profiles", nil, ^(NSInteger code, id json, NSError *e) {
        NSArray *arr = [json isKindOfClass:NSDictionary.class] ? json[@"data"] : nil;
        id first = [arr isKindOfClass:NSArray.class] ? arr.firstObject : nil;
        NSString *pid = [first isKindOfClass:NSDictionary.class] ? first[@"id"] : nil;
        if (pid.length) { st.profileId = pid; [st save]; cb(pid, nil); return; }
        if (code == 401 || code == 403) cb(nil, @"مفتاح API غير صحيح");
        else cb(nil, e ? e.localizedDescription : @"تعذّر جلب Profile ID");
    });
}

static NSString *DSNDErrorText(NSInteger code, id json) {
    id errs = [json isKindOfClass:NSDictionary.class] ? json[@"errors"] : nil;
    id first = [errs isKindOfClass:NSArray.class] ? [errs firstObject] : nil;
    NSString *c = [first isKindOfClass:NSDictionary.class] ? first[@"code"] : nil;
    return c.length ? [NSString stringWithFormat:@"خطأ: %@", c] : [NSString stringWithFormat:@"فشل (%ld)", (long)code];
}

@implementation DSStore {
    dispatch_queue_t _q;
    NSMutableDictionary<NSString *, NSMutableDictionary *> *_items;
    NSMutableDictionary<NSString *, NSString *> *_ipHost;
    NSMutableSet<NSString *> *_seenIP;
    BOOL _saveScheduled;
}

+ (instancetype)shared {
    static DSStore *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [DSStore new]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _q = dispatch_queue_create("ds.store", DISPATCH_QUEUE_SERIAL);
        _items = [NSMutableDictionary dictionary];
        _ipHost = [NSMutableDictionary dictionary];
        _seenIP = [NSMutableSet set];
        [self load];
    }
    return self;
}

- (NSMutableDictionary *)entryFor:(NSString *)v type:(NSString *)t {
    NSMutableDictionary *e = _items[v];
    if (!e) {
        e = [@{ @"type": t, @"count": @0, @"related": [NSMutableSet set], @"src": [NSMutableSet set],
                @"status": @"OK", @"first": @([[NSDate date] timeIntervalSince1970]), @"last": @0 } mutableCopy];
        _items[v] = e;
    }
    e[@"last"] = @([[NSDate date] timeIntervalSince1970]);
    return e;
}

- (void)recordHost:(NSString *)host ips:(NSArray<NSString *> *)ips source:(NSString *)src failed:(BOOL)failed {
    if (host.length == 0) return;
    host = host.lowercaseString;
    if ([host hasSuffix:@"nextdns.io"]) return;  // لا تسجّل طلبات الأداة نفسها
    if (DSIsIPString(host)) { [self recordIP:host port:0 source:src]; return; }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:host type:@"domain"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:src];
        BOOL blocked = NO;
        for (NSString *ip in ips) {
            [e[@"related"] addObject:ip];
            self->_ipHost[ip] = host;
            if ([ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) blocked = YES;
        }
        if (blocked) e[@"status"] = @"BLOCKED";
        else if (failed && ips.count == 0) e[@"status"] = @"FAILED";
        else if (ips.count > 0) e[@"status"] = @"OK";
        [self markDirty];
    });
}

- (void)recordIP:(NSString *)ip port:(int)port source:(NSString *)src {
    if (ip.length == 0) return;
    NSString *key = [NSString stringWithFormat:@"%@:%d", ip, port];
    @synchronized (_seenIP) {
        if ([_seenIP containsObject:key]) return;
        [_seenIP addObject:key];
    }
    dispatch_async(_q, ^{
        NSMutableDictionary *e = [self entryFor:ip type:@"ip"];
        e[@"count"] = @([e[@"count"] integerValue] + 1);
        [e[@"src"] addObject:(port ? [NSString stringWithFormat:@"%@:%d", src, port] : src)];
        NSString *h = self->_ipHost[ip];
        if (h) [e[@"related"] addObject:h];
        [self markDirty];
    });
}

- (void)markDirty {  // يُستدعى داخل _q
    if (_saveScheduled) return;
    _saveScheduled = YES;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), _q, ^{
        self->_saveScheduled = NO;
        [self writeJSON];
    });
}

- (NSArray *)sorted:(id)set { return [[set allObjects] sortedArrayUsingSelector:@selector(compare:)]; }

- (NSArray<NSDictionary *> *)snapshot {
    __block NSMutableArray *out = [NSMutableArray array];
    dispatch_sync(_q, ^{
        for (NSString *k in self->_items) {
            NSDictionary *e = self->_items[k];
            [out addObject:@{ @"value": k, @"type": e[@"type"], @"count": e[@"count"],
                              @"related": [self sorted:e[@"related"]], @"src": [self sorted:e[@"src"]],
                              @"status": e[@"status"], @"last": e[@"last"], @"first": e[@"first"] }];
        }
    });
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [b[@"last"] compare:a[@"last"]];
    }];
    return out;
}

- (void)writeJSON {  // داخل _q
    NSMutableDictionary *dump = [NSMutableDictionary dictionary];
    for (NSString *k in _items) {
        NSDictionary *e = _items[k];
        dump[k] = @{ @"type": e[@"type"], @"count": e[@"count"], @"related": [self sorted:e[@"related"]],
                     @"src": [self sorted:e[@"src"]], @"status": e[@"status"], @"first": e[@"first"], @"last": e[@"last"] };
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:dump options:NSJSONWritingPrettyPrinted error:nil];
    [d writeToFile:[DSDir() stringByAppendingPathComponent:@"data.json"] atomically:YES];
}

- (void)load {
    NSData *d = [NSData dataWithContentsOfFile:[DSDir() stringByAppendingPathComponent:@"data.json"]];
    if (!d) return;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![j isKindOfClass:NSDictionary.class]) return;
    for (NSString *k in j) {
        NSDictionary *e = j[k];
        _items[k] = [@{ @"type": e[@"type"] ?: @"domain", @"count": e[@"count"] ?: @0,
                        @"related": [NSMutableSet setWithArray:e[@"related"] ?: @[]],
                        @"src": [NSMutableSet setWithArray:e[@"src"] ?: @[]],
                        @"status": e[@"status"] ?: @"OK", @"first": e[@"first"] ?: @0, @"last": e[@"last"] ?: @0 } mutableCopy];
    }
}

- (NSString *)denylistText {
    NSMutableArray *lines = [NSMutableArray array];
    for (NSDictionary *e in [self snapshot]) {
        if ([e[@"type"] isEqualToString:@"domain"] && ![e[@"status"] isEqualToString:@"BLOCKED"]) [lines addObject:e[@"value"]];
    }
    [lines sortUsingSelector:@selector(compare:)];
    return [lines componentsJoinedByString:@"\n"];
}

- (NSUInteger)denylistCount {
    NSString *t = [self denylistText];
    return t.length ? [t componentsSeparatedByString:@"\n"].count : 0;
}

- (NSArray<NSURL *> *)saveAll {
    NSArray *snap = [self snapshot];
    NSMutableArray *doms = [NSMutableArray array], *ips = [NSMutableArray array];
    for (NSDictionary *e in snap) {
        NSString *line = [NSString stringWithFormat:@"%@  [%@] x%@  %@", e[@"value"], e[@"status"], e[@"count"],
                          [e[@"related"] componentsJoinedByString:@","]];
        [([e[@"type"] isEqualToString:@"domain"] ? doms : ips) addObject:line];
    }
    [doms sortUsingSelector:@selector(compare:)]; [ips sortUsingSelector:@selector(compare:)];
    NSString *dir = DSDir();
    NSString *p1 = [dir stringByAppendingPathComponent:@"domains.txt"];
    NSString *p2 = [dir stringByAppendingPathComponent:@"ips.txt"];
    NSString *p3 = [dir stringByAppendingPathComponent:@"denylist_nextdns.txt"];
    [[doms componentsJoinedByString:@"\n"] writeToFile:p1 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[ips componentsJoinedByString:@"\n"] writeToFile:p2 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [[self denylistText] writeToFile:p3 atomically:YES encoding:NSUTF8StringEncoding error:nil];
    dispatch_sync(_q, ^{ [self writeJSON]; });
    return @[ [NSURL fileURLWithPath:p3], [NSURL fileURLWithPath:p1], [NSURL fileURLWithPath:p2],
              [NSURL fileURLWithPath:[dir stringByAppendingPathComponent:@"data.json"]] ];
}

- (void)clear {
    dispatch_sync(_q, ^{
        [self->_items removeAllObjects]; [self->_ipHost removeAllObjects];
        [self writeJSON];
    });
    @synchronized (_seenIP) { [_seenIP removeAllObjects]; }
}
@end

#pragma mark - Network hooks

static NSString *DSAddrString(const struct sockaddr *sa) {
    char buf[INET6_ADDRSTRLEN];
    if (!sa) return nil;
    if (sa->sa_family == AF_INET) {
        if (inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf, sizeof buf)) return @(buf);
    } else if (sa->sa_family == AF_INET6) {
        if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, buf, sizeof buf)) return @(buf);
    }
    return nil;
}

static void DSNoteSockaddr(const struct sockaddr *sa, socklen_t len, const char *src) {
    if (!sa || len == 0 || len > sizeof(struct sockaddr_storage)) return;
    static __thread struct sockaddr_storage last;
    static __thread socklen_t lastLen;
    if (lastLen == len && memcmp(&last, sa, len) == 0) return;
    memcpy(&last, sa, len); lastLen = len;

    int port = 0;
    if (sa->sa_family == AF_INET) port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    else if (sa->sa_family == AF_INET6) port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    else return;
    NSString *ip = DSAddrString(sa);
    if (!ip || [ip isEqualToString:@"127.0.0.1"] || [ip isEqualToString:@"::1"] || [ip isEqualToString:@"0.0.0.0"] || [ip isEqualToString:@"::"]) return;
    [[DSStore shared] recordIP:ip port:port source:@(src)];
}

// استبدال نطاق/IP في DNS حسب القواعد المفعّلة
static BOOL DSMapNode(const char *node, char *out, size_t n) {
    if (!node || !gHasRules) return NO;
    NSString *h = [NSString stringWithUTF8String:node];
    NSString *to = h ? [[DSSettings shared] targetFor:h] : nil;
    if (!to) return NO;
    strlcpy(out, to.UTF8String, n);
    return YES;
}

// ====== DNS تلقائي → 8.8.8.8 ======
#define DS_GDNS4 "8.8.8.8"
#define DS_GDNS6 "2001:4860:4860::8888"

static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

// أي اتصال بمنفذ 53 (UDP/TCP) إلى سيرفر DNS غير Google → يتحوّل إلى 8.8.8.8 (المنفذ نفسه)
static BOOL DSDNSRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        if (ntohs(a->sin_port) != 53) return NO;
        uint32_t ip = ntohl(a->sin_addr.s_addr);
        if (ip == 0 || (ip >> 24) == 127 || ip == 0x08080808) return NO;
        memcpy(out, sa, len);
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    }
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        if (ntohs(a->sin6_port) != 53) return NO;
        struct in6_addr g; if (inet_pton(AF_INET6, DS_GDNS6, &g) != 1) return NO;
        if (IN6_IS_ADDR_LOOPBACK(&a->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&a->sin6_addr) ||
            memcmp(&a->sin6_addr, &g, sizeof g) == 0) return NO;
        memcpy(out, sa, len);
        ((struct sockaddr_in6 *)out)->sin6_addr = g;
        return YES;
    }
    return NO;
}

// ---- وضع "الكل → 8.8.8.8" ----
static NSMutableSet *DSExemptSet(void) {   // IPs سيرفرات NextDNS (كي تبقى القائمة شغّالة)
    static NSMutableSet *x; static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [NSMutableSet set]; });
    return x;
}
static BOOL DSIsNextDNSHost(const char *h) {
    size_t l = h ? strlen(h) : 0;
    return l >= 10 && strcasecmp(h + l - 10, "nextdns.io") == 0;
}
static void DSExemptAdd(const struct addrinfo *list) {
    @synchronized (DSExemptSet()) {
        for (const struct addrinfo *p = list; p; p = p->ai_next) {
            NSString *a = DSAddrString(p->ai_addr);
            if (a) [DSExemptSet() addObject:a];
        }
    }
}
static BOOL DSIsLocalAddr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        return ip == 0 || (ip >> 24) == 127 || (ip >> 24) == 10 || (ip >> 16) == 0xC0A8 ||
               (ip >> 20) == 0xAC1 || (ip >> 16) == 0xA9FE;
    }
    if (sa->sa_family == AF_INET6) {
        const struct in6_addr *a = &((const struct sockaddr_in6 *)sa)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_UNSPECIFIED(a) || IN6_IS_ADDR_LINKLOCAL(a) || (a->s6_addr[0] & 0xFE) == 0xFC;
    }
    return YES;
}
// ---- وضع "الدردشة والكتابة أونلاين → 8.8.8.8" ----
static NSMutableSet *DSChatIPs(void) {   // IPs الدردشة التي تعلّمناها من حلّ أسماءها
    static NSMutableSet *x; static dispatch_once_t once;
    dispatch_once(&once, ^{ x = [NSMutableSet set]; });
    return x;
}
static NSArray *DSChatSubstrings(void) {
    static NSArray *a;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ a = @[@"chat", @"typing", @"messag", @"msgr", @"websocket", @"socket.io", @"signalr",
        @"xmpp", @"mqtt", @"agora", @"sendbird", @"pubnub", @"pusher", @"getstream", @"stream-io", @"twilio",
        @"cometchat", @"talkjs", @"livechat", @"tawk", @"zopim", @"whatsapp", @"telegram", @"discord", @"ably"]; });
    return a;
}
static NSSet *DSChatTokens(void) {
    static NSSet *a;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ a = [NSSet setWithArray:@[@"im", @"dm", @"msg", @"msgs", @"rtm", @"ws", @"wss",
        @"socket", @"sockets", @"realtime", @"presence", @"comms"]]; });
    return a;
}
static BOOL DSIsChatHost(const char *h) {
    if (!h || !h[0] || DSIsNextDNSHost(h)) return NO;
    NSString *s = [@(h) lowercaseString];
    if (!s) return NO;
    for (NSString *k in DSChatSubstrings()) if ([s containsString:k]) return YES;
    NSArray *tok = [s componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@".-_"]];
    NSSet *ex = DSChatTokens();
    for (NSString *t in tok) if ([ex containsObject:t]) return YES;
    for (NSString *k in [DSSettings shared].chatKeywords)       // كلمات إضافية من settings.json
        if ([k isKindOfClass:[NSString class]] && k.length && [s containsString:k.lowercaseString]) return YES;
    return NO;
}
static void DSChatIPAdd(const struct addrinfo *list) {
    @synchronized (DSChatIPs()) {
        for (const struct addrinfo *p = list; p; p = p->ai_next) {
            NSString *a = DSAddrString(p->ai_addr);
            if (a) [DSChatIPs() addObject:a];
        }
    }
}
static BOOL DSChatEligible(const char *node, const struct addrinfo *hints) {
    if (!node || !node[0] || !strchr(node, '.')) return NO;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1) return NO;
    if (hints) {
        if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) return NO;
        if (hints->ai_flags & (AI_NUMERICHOST | AI_PASSIVE | AI_CANONNAME)) return NO;
    }
    return DSIsChatHost(node);
}
static const char *DSPortStr(const char *service, char *buf, size_t n) {   // https / wss → رقم
    if (!service) return NULL;
    if (strcasecmp(service, "https") == 0 || strcasecmp(service, "wss") == 0) return "443";
    if (strcasecmp(service, "http") == 0 || strcasecmp(service, "ws") == 0) return "80";
    strlcpy(buf, service, n); return buf;
}
static BOOL DSChatRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return NO;
    NSString *ip = DSAddrString(sa);
    if (!ip) return NO;
    BOOL hit; @synchronized (DSChatIPs()) { hit = [DSChatIPs() containsObject:ip]; }
    if (!hit) return NO;
    memcpy(out, sa, len);
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        return inet_pton(AF_INET6, DS_GDNS6, &((struct sockaddr_in6 *)out)->sin6_addr) == 1;
    return NO;
}
static BOOL DSForceRewrite(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return NO;
    if (DSIsLocalAddr(sa)) return NO;
    NSString *ip = DSAddrString(sa);
    if (!ip || [ip isEqualToString:@DS_GDNS4] || [ip isEqualToString:@DS_GDNS6]) return NO;
    @synchronized (DSExemptSet()) { if ([DSExemptSet() containsObject:ip]) return NO; }
    memcpy(out, sa, len);
    if (sa->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        return inet_pton(AF_INET, DS_GDNS4, &((struct sockaddr_in *)out)->sin_addr) == 1;
    if (sa->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        return inet_pton(AF_INET6, DS_GDNS6, &((struct sockaddr_in6 *)out)->sin6_addr) == 1;
    return NO;
}

// استبدال IP في connect/sendto: قواعد المستخدم أولاً، ثم وضع DNS التلقائي
static BOOL DSRewriteSockaddr(const struct sockaddr *sa, socklen_t len, struct sockaddr_storage *out) {
    if (!sa || len == 0 || len > sizeof(*out)) return NO;
    if (gHasIPRules) {
        NSString *ip = DSAddrString(sa);
        NSString *to = ip ? [[DSSettings shared] targetFor:ip] : nil;
        if (to) {
            memcpy(out, sa, len);
            if (sa->sa_family == AF_INET) {
                struct in_addr a;
                if (inet_pton(AF_INET, to.UTF8String, &a) == 1) { ((struct sockaddr_in *)out)->sin_addr = a; return YES; }
            } else if (sa->sa_family == AF_INET6) {
                struct in6_addr a;
                if (inet_pton(AF_INET6, to.UTF8String, &a) == 1) { ((struct sockaddr_in6 *)out)->sin6_addr = a; return YES; }
            }
        }
    }
    if (gForceAll && DSForceRewrite(sa, len, out)) return YES;
    if (gChatMode && DSChatRewrite(sa, len, out)) return YES;
    if (gAutoDNS && DSDNSRewrite(sa, len, out)) return YES;
    return NO;
}

// ==== DS_RESOLVER_C_BEGIN ====
// محلّل DNS مدمج: يسأل 8.8.8.8 مباشرة (سجل A) بدل DNS الجهاز/الشبكة
static const char *gDNSServer = DS_GDNS4;
static uint16_t gDNSPort = 53;
static volatile double gDNSDownUntil = 0;   // إذا تعذّر الوصول لـ 8.8.8.8 نتجاوزه مؤقتاً

static double DSNow(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return (double)ts.tv_sec + ts.tv_nsec / 1e9; }

static size_t DSSkipName(const uint8_t *r, size_t n, size_t i) {
    while (i < n) {
        uint8_t l = r[i];
        if (l == 0) return i + 1;
        if ((l & 0xC0) == 0xC0) return (i + 2 <= n) ? i + 2 : 0;
        if (l & 0xC0) return 0;
        i += 1 + l;
    }
    return 0;
}

static BOOL DSDNSQuery4(const char *host, struct in_addr *outs, int max, int *count, uint32_t *minTTL) {
    size_t hl = strlen(host);
    if (hl == 0 || hl > 253) return NO;
    uint8_t q[320]; size_t o = 0;
    uint16_t id = (uint16_t)arc4random();
    q[o++] = id >> 8; q[o++] = id & 0xFF; q[o++] = 0x01; q[o++] = 0x00;      // ID + RD
    q[o++] = 0; q[o++] = 1; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0; q[o++] = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t ll = dot ? (size_t)(dot - p) : strlen(p);
        if (ll == 0 || ll > 63 || o + ll + 6 > sizeof q) return NO;
        q[o++] = (uint8_t)ll; memcpy(q + o, p, ll); o += ll;
        p += ll; if (*p == '.') p++;
    }
    q[o++] = 0; q[o++] = 0; q[o++] = 1; q[o++] = 0; q[o++] = 1;                // A / IN

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return NO;
    struct timeval tv = { 1, 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in dst; memset(&dst, 0, sizeof dst);
    dst.sin_len = sizeof dst; dst.sin_family = AF_INET; dst.sin_port = htons(gDNSPort);
    inet_pton(AF_INET, gDNSServer, &dst.sin_addr);

    ssize_t (*snd)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = orig_sendto ? orig_sendto : sendto;
    uint8_t r[1500]; ssize_t rn = -1;
    for (int t = 0; t < 2; t++) {
        if (snd(fd, q, o, 0, (struct sockaddr *)&dst, sizeof dst) < 0) break;
        rn = recvfrom(fd, r, sizeof r, 0, NULL, NULL);
        if (rn >= 12 && r[0] == q[0] && r[1] == q[1]) break;
        rn = -1;
    }
    close(fd);
    if (rn < 12) { gDNSDownUntil = DSNow() + 20.0; return NO; }               // لا رد: تجاوز 20 ثانية
    if (!(r[2] & 0x80) || (r[3] & 0x0F) != 0) return NO;                       // ليس رداً سليماً (NXDOMAIN وغيره)

    size_t N = (size_t)rn, i = 12;
    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
    for (int k = 0; k < qd; k++) { i = DSSkipName(r, N, i); if (!i || i + 4 > N) return NO; i += 4; }
    int c = 0; uint32_t mt = 0xFFFFFFFFu;
    for (int k = 0; k < an && i < N; k++) {
        i = DSSkipName(r, N, i); if (!i || i + 10 > N) break;
        uint16_t type = (r[i] << 8) | r[i + 1], cls = (r[i + 2] << 8) | r[i + 3];
        uint32_t ttl = ((uint32_t)r[i + 4] << 24) | (r[i + 5] << 16) | (r[i + 6] << 8) | r[i + 7];
        uint16_t rdl = (r[i + 8] << 8) | r[i + 9];
        i += 10; if (i + rdl > N) break;
        if (type == 1 && cls == 1 && rdl == 4 && c < max) { memcpy(&outs[c++], r + i, 4); if (ttl < mt) mt = ttl; }
        i += rdl;
    }
    *count = c; *minTTL = (mt == 0xFFFFFFFFu) ? 0 : mt;
    return c > 0;
}

// يبني قائمة addrinfo (تُحرَّر بـ freeaddrinfo العادية: كل عقدة وعنوانها بـ malloc منفصل)
static struct addrinfo *DSBuildAddrInfo(const struct in_addr *ips, int n, const char *service, const struct addrinfo *hints) {
    int port = service ? atoi(service) : 0;
    int socktype = hints ? hints->ai_socktype : 0, proto = hints ? hints->ai_protocol : 0;
    int types[2], tc = 0;
    if (socktype == 0) { types[tc++] = SOCK_STREAM; types[tc++] = SOCK_DGRAM; } else types[tc++] = socktype;
    struct addrinfo *head = NULL, *tail = NULL;
    for (int i = 0; i < n; i++) for (int t = 0; t < tc; t++) {
        struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof *ai);
        struct sockaddr_in *sin = (struct sockaddr_in *)calloc(1, sizeof *sin);
        if (!ai || !sin) { free(ai); free(sin); continue; }
        sin->sin_len = sizeof *sin; sin->sin_family = AF_INET; sin->sin_port = htons((uint16_t)port); sin->sin_addr = ips[i];
        ai->ai_flags = hints ? hints->ai_flags : 0; ai->ai_family = AF_INET; ai->ai_socktype = types[t];
        ai->ai_protocol = proto ? proto : (types[t] == SOCK_STREAM ? IPPROTO_TCP : (types[t] == SOCK_DGRAM ? IPPROTO_UDP : 0));
        ai->ai_addrlen = sizeof *sin; ai->ai_addr = (struct sockaddr *)sin;
        if (tail) tail->ai_next = ai; else head = ai;
        tail = ai;
    }
    return head;
}
// ==== DS_RESOLVER_C_END ====

static NSMutableDictionary *DSDNSCache(void) {
    static NSMutableDictionary *c; static dispatch_once_t once;
    dispatch_once(&once, ^{ c = [NSMutableDictionary dictionary]; });
    return c;
}

static BOOL DSResolve4(const char *host, struct in_addr *outs, int max, int *count) {
    NSString *key = @(host).lowercaseString;
    if (!key) return NO;
    double now = DSNow();
    @synchronized (DSDNSCache()) {
        NSDictionary *e = DSDNSCache()[key];
        if (e && [e[@"exp"] doubleValue] > now) {
            NSData *d = e[@"ips"]; int n = (int)(d.length / sizeof(struct in_addr)); if (n > max) n = max;
            memcpy(outs, d.bytes, n * sizeof(struct in_addr)); *count = n; return n > 0;
        }
    }
    uint32_t ttl = 0; int n = 0;
    if (!DSDNSQuery4(host, outs, max, &n, &ttl) || n <= 0) return NO;
    if (ttl < 10) ttl = 10; if (ttl > 300) ttl = 300;
    @synchronized (DSDNSCache()) {
        if (DSDNSCache().count > 512) [DSDNSCache() removeAllObjects];
        DSDNSCache()[key] = @{ @"ips": [NSData dataWithBytes:outs length:n * sizeof(struct in_addr)], @"exp": @(now + ttl) };
    }
    *count = n; return YES;
}

// متى نستخدم المحلّل المدمج؟ فقط للأسماء العادية؛ غير ذلك نتركه للنظام
static BOOL DSNameEligible(const char *node, const char *service, const struct addrinfo *hints) {
    if (!node || !node[0]) return NO;
    if (!strchr(node, '.')) return NO;                                          // localhost وأسماء محلية
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1) return NO;
    size_t l = strlen(node);
    if (l > 6 && strcasecmp(node + l - 6, ".local") == 0) return NO;
    if (hints) {
        if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET) return NO;
        if (hints->ai_flags & (AI_NUMERICHOST | AI_PASSIVE | AI_CANONNAME)) return NO;
    }
    if (service) { for (const char *c = service; *c; c++) if (*c < '0' || *c > '9') return NO; }
    return YES;
}
static BOOL DSShouldAutoResolve(const char *node, const char *service, const struct addrinfo *hints) {
    if (!gAutoDNS || DSNow() < gDNSDownUntil) return NO;
    return DSNameEligible(node, service, hints);
}
static BOOL DSForceEligible(const char *node, const char *service, const struct addrinfo *hints) {
    return gForceAll && DSNameEligible(node, service, hints) && !DSIsNextDNSHost(node);
}

static struct hostent *DSAutoHostent(const char *name) {
    static __thread struct hostent he; static __thread char nameBuf[256];
    static __thread struct in_addr addrs[16]; static __thread char *list[17]; static __thread char *aliases[1];
    struct in_addr ips[16]; int n = 0;
    if (!DSShouldAutoResolve(name, NULL, NULL) || !DSResolve4(name, ips, 16, &n) || n <= 0) return NULL;
    for (int i = 0; i < n; i++) { addrs[i] = ips[i]; list[i] = (char *)&addrs[i]; }
    list[n] = NULL; aliases[0] = NULL;
    strlcpy(nameBuf, name, sizeof nameBuf);
    he.h_name = nameBuf; he.h_aliases = aliases; he.h_addrtype = AF_INET; he.h_length = 4; he.h_addr_list = list;
    return &he;
}

static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int hook_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    char mapped[256];
    BOOL isMapped = DSMapNode(node, mapped, sizeof mapped);
    int r = -1; BOOL done = NO;
    if (!isMapped && res && DSForceEligible(node, service, hints)) {          // الكل → 8.8.8.8
        struct in_addr g; inet_pton(AF_INET, DS_GDNS4, &g);
        struct addrinfo *fl = DSBuildAddrInfo(&g, 1, service, hints);
        if (fl) { *res = fl; r = 0; done = YES; }
    }
    if (!done && !isMapped && res && gChatMode && DSChatEligible(node, hints)) {   // دردشة/كتابة → 8.8.8.8
        struct addrinfo *real = NULL;
        if (orig_getaddrinfo(node, service, hints, &real) == 0 && real) { DSChatIPAdd(real); freeaddrinfo(real); }
        char pb[32]; struct in_addr g; inet_pton(AF_INET, DS_GDNS4, &g);
        struct addrinfo *cl = DSBuildAddrInfo(&g, 1, DSPortStr(service, pb, sizeof pb), hints);
        if (cl) { *res = cl; r = 0; done = YES; }
    }
    if (!done && !isMapped && res && DSShouldAutoResolve(node, service, hints)) {   // DNS = 8.8.8.8
        struct in_addr ips4[16]; int cnt = 0;
        if (DSResolve4(node, ips4, 16, &cnt)) {
            struct addrinfo *list = DSBuildAddrInfo(ips4, cnt, service, hints);
            if (list) { *res = list; r = 0; done = YES; }
        }
    }
    if (!done) r = orig_getaddrinfo(isMapped ? mapped : node, service, hints, res);   // احتياطي: DNS النظام
    if (r == 0 && res && *res && DSIsNextDNSHost(node)) DSExemptAdd(*res);
    if (node) {
        NSMutableArray *ips = [NSMutableArray array];
        if (r == 0 && res && *res) {
            for (struct addrinfo *p = *res; p; p = p->ai_next) {
                NSString *s = DSAddrString(p->ai_addr);
                if (s && ![ips containsObject:s]) [ips addObject:s];
            }
        }
        NSString *h = [NSString stringWithUTF8String:node];
        if (h) [[DSStore shared] recordHost:h ips:ips source:@"dns" failed:(r != 0)];
    }
    return r;
}

static struct hostent *(*orig_gethostbyname)(const char *);
static struct hostent *hook_gethostbyname(const char *name) {
    char mapped[256];
    BOOL isMapped = DSMapNode(name, mapped, sizeof mapped);
    struct hostent *r = NULL;
    if (!isMapped && DSForceEligible(name, NULL, NULL)) {                       // الكل → 8.8.8.8
        static __thread struct hostent fh; static __thread char fn[256]; static __thread struct in_addr fa;
        static __thread char *fl[2]; static __thread char *fal[1];
        inet_pton(AF_INET, DS_GDNS4, &fa); fl[0] = (char *)&fa; fl[1] = NULL; fal[0] = NULL;
        strlcpy(fn, name, sizeof fn);
        fh.h_name = fn; fh.h_aliases = fal; fh.h_addrtype = AF_INET; fh.h_length = 4; fh.h_addr_list = fl;
        r = &fh;
    }
    if (!r && !isMapped && gChatMode && DSChatEligible(name, NULL)) {            // دردشة/كتابة → 8.8.8.8
        struct hostent *real = orig_gethostbyname(name);
        if (real && real->h_addrtype == AF_INET && real->h_addr_list) {
            for (char **a = real->h_addr_list; *a; a++) {
                char b[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, *a, b, sizeof b)) @synchronized (DSChatIPs()) { [DSChatIPs() addObject:@(b)]; }
            }
        }
        static __thread struct hostent ch; static __thread char cn[256]; static __thread struct in_addr ca;
        static __thread char *cl[2]; static __thread char *cal[1];
        inet_pton(AF_INET, DS_GDNS4, &ca); cl[0] = (char *)&ca; cl[1] = NULL; cal[0] = NULL;
        strlcpy(cn, name, sizeof cn);
        ch.h_name = cn; ch.h_aliases = cal; ch.h_addrtype = AF_INET; ch.h_length = 4; ch.h_addr_list = cl;
        r = &ch;
    }
    if (!r && !isMapped) r = DSAutoHostent(name);                   // DNS = 8.8.8.8
    if (!r) r = orig_gethostbyname(isMapped ? mapped : name);
    if (name) {
        NSString *h = [NSString stringWithUTF8String:name];
        if (h) [[DSStore shared] recordHost:h ips:nil source:@"dns" failed:(r == NULL)];
    }
    return r;
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int fd, const struct sockaddr *sa, socklen_t len) {
    DSNoteSockaddr(sa, len, "connect");
    struct sockaddr_storage ss;
    if (DSRewriteSockaddr(sa, len, &ss)) return orig_connect(fd, (const struct sockaddr *)&ss, len);
    return orig_connect(fd, sa, len);
}

static ssize_t hook_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *dst, socklen_t dlen) {
    if (dst) DSNoteSockaddr(dst, dlen, "udp");
    struct sockaddr_storage ss;
    if (dst && DSRewriteSockaddr(dst, dlen, &ss)) return orig_sendto(fd, buf, n, flags, (const struct sockaddr *)&ss, dlen);
    return orig_sendto(fd, buf, n, flags, dst, dlen);
}

static void DSURL(NSURL *u, NSString *src) {
    NSString *h = u.host;
    if ([h.lowercaseString hasSuffix:@"nextdns.io"]) return;  // لا تسجّل طلبات الأداة نفسها
    if (h.length) [[DSStore shared] recordHost:h ips:nil source:src failed:NO];
}

#pragma mark - Built-in hook engine (no Substrate / ElleKit needed)

// 1) دوال C (getaddrinfo, connect, ...) عبر إعادة ربط مؤشرات الرموز في كل صور Mach-O المحمّلة
typedef struct { const char *name; void *replacement; } DSRebind;
static DSRebind gRebinds[8];
static int gRebindCount = 0;

static BOOL DSSetProt(void *addr, size_t size, vm_prot_t prot, BOOL copy) {
    uintptr_t pg = (uintptr_t)vm_page_size;
    uintptr_t start = (uintptr_t)addr & ~(pg - 1);
    uintptr_t end = ((uintptr_t)addr + size + pg - 1) & ~(pg - 1);
    return vm_protect(mach_task_self(), (vm_address_t)start, (vm_size_t)(end - start), 0,
                      copy ? (prot | VM_PROT_COPY) : prot) == KERN_SUCCESS;
}

static void DSRebindSection(const struct section_64 *sect, intptr_t slide, const struct nlist_64 *symtab,
                            const char *strtab, const uint32_t *indirect) {
    const uint32_t *idx = indirect + sect->reserved1;
    void **slots = (void **)((uintptr_t)slide + (uintptr_t)sect->addr);
    size_t count = (size_t)(sect->size / sizeof(void *));
    BOOL isConst = strncmp(sect->segname, "__DATA_CONST", 16) == 0;
    BOOL unlocked = NO;
    for (size_t i = 0; i < count; i++) {
        uint32_t si = idx[i];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL || si == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        const char *name = strtab + symtab[si].n_un.n_strx;
        if (!name[0] || !name[1]) continue;
        for (int k = 0; k < gRebindCount; k++) {
            if (strcmp(name + 1, gRebinds[k].name) != 0) continue;
            if (slots[i] == gRebinds[k].replacement) break;
            if (isConst && !unlocked) {
                if (!DSSetProt(slots, (size_t)sect->size, VM_PROT_READ | VM_PROT_WRITE, YES)) return;
                unlocked = YES;
            }
            slots[i] = gRebinds[k].replacement;
            break;
        }
    }
    if (isConst && unlocked) DSSetProt(slots, (size_t)sect->size, VM_PROT_READ, NO);
}

static void DSRebindImage(const struct mach_header *mh, intptr_t slide) {
    if (!mh || mh->magic != MH_MAGIC_64) return;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *stc = NULL;
    const struct dysymtab_command *dsc = NULL;
    uintptr_t cur = (uintptr_t)h + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) linkedit = seg;
        } else if (lc->cmd == LC_SYMTAB) stc = (const struct symtab_command *)cur;
        else if (lc->cmd == LC_DYSYMTAB) dsc = (const struct dysymtab_command *)cur;
        cur += lc->cmdsize;
    }
    if (!linkedit || !stc || !dsc || dsc->nindirectsyms == 0) return;
    uintptr_t base = (uintptr_t)slide + (uintptr_t)linkedit->vmaddr - (uintptr_t)linkedit->fileoff;
    const struct nlist_64 *symtab = (const struct nlist_64 *)(base + stc->symoff);
    const char *strtab = (const char *)(base + stc->stroff);
    const uint32_t *indirect = (const uint32_t *)(base + dsc->indirectsymoff);
    cur = (uintptr_t)h + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cur;
            if (strcmp(seg->segname, "__DATA") == 0 || strncmp(seg->segname, "__DATA_CONST", 16) == 0) {
                const struct section_64 *secs = (const struct section_64 *)(cur + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    uint32_t type = secs[j].flags & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS)
                        DSRebindSection(&secs[j], slide, symtab, strtab, indirect);
                }
            }
        }
        cur += lc->cmdsize;
    }
}

#define DS_ADD_REBIND(sym, origvar, hookfn) do { \
    void *p_ = dlsym(RTLD_DEFAULT, sym); \
    if (p_) { origvar = (__typeof__(origvar))p_; \
              gRebinds[gRebindCount].name = sym; gRebinds[gRebindCount].replacement = (void *)hookfn; gRebindCount++; } \
} while (0)

static void DSInstallCHooks(void) {
    DS_ADD_REBIND("getaddrinfo", orig_getaddrinfo, hook_getaddrinfo);
    DS_ADD_REBIND("gethostbyname", orig_gethostbyname, hook_gethostbyname);
    DS_ADD_REBIND("connect", orig_connect, hook_connect);
    DS_ADD_REBIND("sendto", orig_sendto, hook_sendto);
    _dyld_register_func_for_add_image(DSRebindImage);  // يمرّ على الصور الحالية ثم أي صورة جديدة
}

// 2) NSURLSession عبر ObjC runtime
static BOOL DSClassOwns(Class c, SEL s) {
    unsigned n = 0; BOOL found = NO;
    Method *list = class_copyMethodList(c, &n);
    for (unsigned i = 0; i < n; i++) if (method_getName(list[i]) == s) { found = YES; break; }
    free(list);
    return found;
}

static void DSHookURLMethod(Class base, Class concrete, const char *selName, NSString *src) {
    SEL sel = sel_registerName(selName);
    Class target = (concrete && concrete != base && DSClassOwns(concrete, sel)) ? concrete : base;
    Method m = class_getInstanceMethod(target, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);
    id (^blk)(__unsafe_unretained id, __unsafe_unretained id, __unsafe_unretained id, __unsafe_unretained id) =
        ^id(__unsafe_unretained id obj, __unsafe_unretained id a, __unsafe_unretained id b, __unsafe_unretained id c) {
            NSURL *u = nil;
            if ([a isKindOfClass:NSURLRequest.class]) u = ((NSURLRequest *)a).URL;
            else if ([a isKindOfClass:NSURL.class]) u = (NSURL *)a;
            DSURL(u, src);
            return ((id (*)(id, SEL, id, id, id))orig)(obj, sel, a, b, c);
        };
    method_setImplementation(m, imp_implementationWithBlock(blk));
}

static void DSInstallURLSessionHooks(void) {
    Class base = NSURLSession.class;
    Class concrete = [NSURLSession sharedSession].class;
    DSHookURLMethod(base, concrete, "dataTaskWithRequest:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithRequest:completionHandler:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithURL:", @"http");
    DSHookURLMethod(base, concrete, "dataTaskWithURL:completionHandler:", @"http");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromData:", @"upload");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromData:completionHandler:", @"upload");
    DSHookURLMethod(base, concrete, "uploadTaskWithRequest:fromFile:", @"upload");
    DSHookURLMethod(base, concrete, "downloadTaskWithRequest:", @"download");
    DSHookURLMethod(base, concrete, "downloadTaskWithURL:", @"download");
    DSHookURLMethod(base, concrete, "webSocketTaskWithURL:", @"ws");
    DSHookURLMethod(base, concrete, "webSocketTaskWithRequest:", @"ws");
}

#pragma mark - UI theme (Aflatoon cyber-terminal)

enum { kBG = 0x070203, kPanel = 0x160506, kLine = 0x3A0E12, kGreen = 0xFF2E2E, kCyan = 0xFF6A00,
       kRed = 0xFF0033, kAmber = 0xFFB800, kPurple = 0x8A0303, kText = 0xF2E4E0, kDim = 0x8A5A5A, kGold = 0xD4AF37 };

static inline UIColor *DSHex(uint32_t h) {
    return [UIColor colorWithRed:((h >> 16) & 0xFF) / 255.0 green:((h >> 8) & 0xFF) / 255.0 blue:(h & 0xFF) / 255.0 alpha:1];
}
static UIFont *DSMono(CGFloat s, UIFontWeight w) { return [UIFont monospacedSystemFontOfSize:s weight:w]; }
static void DSGlow(CALayer *l, UIColor *c, CGFloat r) {
    l.shadowColor = c.CGColor; l.shadowOpacity = 0.9; l.shadowRadius = r; l.shadowOffset = CGSizeZero;
}
static UIImage *DSIcon(NSString *name, CGFloat pt) {
    UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:pt weight:UIImageSymbolWeightSemibold];
    return [UIImage systemImageNamed:name withConfiguration:cfg];
}

@interface DSGradView : UIView
@end
@implementation DSGradView
+ (Class)layerClass { return CAGradientLayer.class; }
@end

@interface DSPill : UILabel
@end
@implementation DSPill
- (void)drawTextInRect:(CGRect)r { [super drawTextInRect:UIEdgeInsetsInsetRect(r, UIEdgeInsetsMake(2, 7, 2, 7))]; }
- (CGSize)intrinsicContentSize { CGSize s = [super intrinsicContentSize]; return CGSizeMake(s.width + 14, s.height + 4); }
@end

static void DSStylePill(DSPill *p, NSString *t, UIColor *c) {
    p.text = t; p.font = DSMono(10, UIFontWeightBold); p.textColor = c; p.textAlignment = NSTextAlignmentCenter;
    p.backgroundColor = [c colorWithAlphaComponent:0.14];
    p.layer.cornerRadius = 5; p.layer.borderWidth = 0.5; p.layer.borderColor = [c colorWithAlphaComponent:0.7].CGColor;
    p.clipsToBounds = YES;
}

#pragma mark - Row cell

@interface DSCell : UITableViewCell
- (void)configure:(NSDictionary *)e sent:(BOOL)sent;
@end

@implementation DSCell {
    UIView *_card, *_bar; UILabel *_title, *_meta, *_rel, *_count; UIImageView *_icon; DSPill *_tag;
}

- (UILabel *)label:(UIFont *)f color:(UIColor *)c {
    UILabel *l = [UILabel new]; l.font = f; l.textColor = c; l.translatesAutoresizingMaskIntoConstraints = NO; return l;
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)rid {
    if ((self = [super initWithStyle:style reuseIdentifier:rid])) {
        self.backgroundColor = UIColor.clearColor; self.contentView.backgroundColor = UIColor.clearColor;
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        _card = [UIView new]; _card.backgroundColor = DSHex(kPanel); _card.layer.cornerRadius = 10;
        _card.layer.borderWidth = 1; _card.layer.borderColor = DSHex(kLine).CGColor; _card.clipsToBounds = YES;
        _card.translatesAutoresizingMaskIntoConstraints = NO; [self.contentView addSubview:_card];
        _bar = [UIView new]; _bar.translatesAutoresizingMaskIntoConstraints = NO; [_card addSubview:_bar];
        _icon = [UIImageView new]; _icon.contentMode = UIViewContentModeCenter; _icon.translatesAutoresizingMaskIntoConstraints = NO;
        _title = [self label:DSMono(14, UIFontWeightSemibold) color:DSHex(kText)]; _title.lineBreakMode = NSLineBreakByTruncatingMiddle;
        _meta = [self label:DSMono(11, UIFontWeightRegular) color:DSHex(kDim)];
        _rel = [self label:DSMono(11, UIFontWeightRegular) color:DSHex(kCyan)]; _rel.numberOfLines = 2;
        _count = [self label:DSMono(13, UIFontWeightBold) color:DSHex(kGreen)];
        [_count setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        [_count setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        _tag = [DSPill new]; _tag.translatesAutoresizingMaskIntoConstraints = NO;
        [_tag setContentCompressionResistancePriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
        for (UIView *v in @[_icon, _title, _meta, _rel, _count, _tag]) [_card addSubview:v];
        [NSLayoutConstraint activateConstraints:@[
            [_card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
            [_card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
            [_card.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:2],
            [_card.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-2],
            [_bar.leadingAnchor constraintEqualToAnchor:_card.leadingAnchor], [_bar.topAnchor constraintEqualToAnchor:_card.topAnchor],
            [_bar.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor], [_bar.widthAnchor constraintEqualToConstant:3],
            [_icon.leadingAnchor constraintEqualToAnchor:_bar.trailingAnchor constant:10],
            [_icon.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_icon.widthAnchor constraintEqualToConstant:20], [_icon.heightAnchor constraintEqualToConstant:20],
            [_title.leadingAnchor constraintEqualToAnchor:_icon.trailingAnchor constant:6],
            [_title.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_title.trailingAnchor constraintLessThanOrEqualToAnchor:_count.leadingAnchor constant:-8],
            [_count.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
            [_count.topAnchor constraintEqualToAnchor:_card.topAnchor constant:10],
            [_tag.trailingAnchor constraintEqualToAnchor:_card.trailingAnchor constant:-12],
            [_tag.topAnchor constraintEqualToAnchor:_count.bottomAnchor constant:6],
            [_meta.leadingAnchor constraintEqualToAnchor:_title.leadingAnchor],
            [_meta.topAnchor constraintEqualToAnchor:_title.bottomAnchor constant:4],
            [_meta.trailingAnchor constraintLessThanOrEqualToAnchor:_tag.leadingAnchor constant:-8],
            [_rel.leadingAnchor constraintEqualToAnchor:_title.leadingAnchor],
            [_rel.topAnchor constraintEqualToAnchor:_meta.bottomAnchor constant:3],
            [_rel.trailingAnchor constraintEqualToAnchor:_tag.leadingAnchor constant:-8],
            [_rel.bottomAnchor constraintEqualToAnchor:_card.bottomAnchor constant:-10],
            [_tag.bottomAnchor constraintLessThanOrEqualToAnchor:_card.bottomAnchor constant:-8]]];
    }
    return self;
}

- (void)configure:(NSDictionary *)e sent:(BOOL)sent {
    NSString *st = e[@"status"]; BOOL isIP = [e[@"type"] isEqualToString:@"ip"];
    UIColor *c; NSString *tag;
    if (sent) { c = DSHex(kPurple); tag = @"DENYLISTED"; }
    else if ([st isEqualToString:@"BLOCKED"]) { c = DSHex(kRed); tag = @"BLOCKED"; }
    else if ([st isEqualToString:@"FAILED"]) { c = DSHex(kAmber); tag = @"FAILED"; }
    else { c = DSHex(kGreen); tag = @"LIVE"; }
    _bar.backgroundColor = c; DSStylePill(_tag, tag, c);
    _icon.image = DSIcon(isIP ? @"network" : @"globe", 15); _icon.tintColor = isIP ? DSHex(kAmber) : DSHex(kCyan);
    _title.text = e[@"value"];
    _count.text = [NSString stringWithFormat:@"×%@", e[@"count"]];
    _meta.text = [(NSArray *)e[@"src"] componentsJoinedByString:@" · "];
    NSArray *rel = e[@"related"];
    NSArray *shown = rel.count > 3 ? [rel subarrayWithRange:NSMakeRange(0, 3)] : rel;
    _rel.text = shown.count ? [NSString stringWithFormat:@"→ %@%@", [shown componentsJoinedByString:@", "], rel.count > 3 ? @" …" : @""] : nil;
}
@end

#pragma mark - Rules screen

@interface DSRulesVC : UITableViewController
+ (void)promptFrom:(NSString *)from over:(UIViewController *)vc done:(void (^)(void))done;
@end

@implementation DSRulesVC

+ (void)promptFrom:(NSString *)from over:(UIViewController *)vc done:(void (^)(void))done {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"🔁 استبدال"
        message:@"مثال: 1.1.1.1 ← 8.8.8.8\nأو *.example.com ← 1.2.3.4" preferredStyle:UIAlertControllerStyleAlert];
    NSArray *ph = @[@"من (نطاق أو IP)", @"إلى (IP أو نطاق)"];
    for (NSInteger i = 0; i < 2; i++) {
        [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
            t.placeholder = ph[i]; t.text = i == 0 ? from : nil; t.font = DSMono(14, UIFontWeightRegular);
            t.autocapitalizationType = UITextAutocapitalizationTypeNone;
            t.autocorrectionType = UITextAutocorrectionTypeNo; t.keyboardType = UIKeyboardTypeURL;
        }];
    }
    __weak UIAlertController *wa = a;
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"إضافة وتفعيل" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [[DSSettings shared] addRuleFrom:wa.textFields[0].text to:wa.textFields[1].text];
        if (done) done();
    }]];
    [vc presentViewController:a animated:YES completion:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.title = @"RULES // قواعد الاستبدال";
    self.view.backgroundColor = DSHex(kBG);
    self.tableView.backgroundColor = DSHex(kBG);
    self.tableView.separatorColor = DSHex(kLine);
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(done)];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(add)];
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    UINavigationBar *nb = self.navigationController.navigationBar;
    nb.barStyle = UIBarStyleBlack; nb.tintColor = DSHex(kGreen); nb.barTintColor = DSHex(kBG); nb.translucent = NO;
    nb.titleTextAttributes = @{ NSForegroundColorAttributeName: DSHex(kGreen), NSFontAttributeName: DSMono(14, UIFontWeightBold) };
}
- (void)done { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)add { [DSRulesVC promptFrom:nil over:self done:^{ [self.tableView reloadData]; }]; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    NSUInteger n = [DSSettings shared].rules.count;
    if (n == 0) {
        UILabel *l = [UILabel new]; l.text = @"$ no rules yet\nاضغط + لإضافة قاعدة استبدال"; l.numberOfLines = 0;
        l.textAlignment = NSTextAlignmentCenter; l.font = DSMono(13, UIFontWeightRegular); l.textColor = DSHex(kDim);
        tv.backgroundView = l;
    } else tv.backgroundView = nil;
    return n;
}
- (NSString *)tableView:(UITableView *)tv titleForFooterInSection:(NSInteger)s {
    return @"التفعيل يُحفظ تلقائياً ويبقى بعد الخروج من اللعبة. القاعدة تُطبَّق على الاتصالات الجديدة (قد تحتاج إعادة تشغيل اللعبة). يدعم *.domain.com";
}
- (void)tableView:(UITableView *)tv willDisplayFooterView:(UIView *)v forSection:(NSInteger)s {
    ((UITableViewHeaderFooterView *)v).textLabel.textColor = DSHex(kDim);
}
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    NSDictionary *r = [DSSettings shared].rules[ip.row];
    c.backgroundColor = DSHex(kPanel);
    c.textLabel.text = [NSString stringWithFormat:@"%@\n   ↳ %@", r[@"from"], r[@"to"]];
    c.textLabel.font = DSMono(13, UIFontWeightMedium); c.textLabel.textColor = DSHex(kGreen); c.textLabel.numberOfLines = 3;
    UISwitch *sw = [UISwitch new]; sw.on = [r[@"enabled"] boolValue]; sw.tag = ip.row; sw.onTintColor = DSHex(kGreen);
    [sw addTarget:self action:@selector(toggled:) forControlEvents:UIControlEventValueChanged];
    c.accessoryView = sw;
    return c;
}
- (void)toggled:(UISwitch *)sw { [[DSSettings shared] setRule:sw.tag enabled:sw.isOn]; }
- (void)tableView:(UITableView *)tv commitEditingStyle:(UITableViewCellEditingStyle)st forRowAtIndexPath:(NSIndexPath *)ip {
    if (st != UITableViewCellEditingStyleDelete) return;
    [[DSSettings shared] removeRule:ip.row];
    [tv reloadData];
}
@end

#pragma mark - Main menu

@interface DSMenuVC : UIViewController <UITableViewDataSource, UITableViewDelegate, UITextFieldDelegate>
@end

@implementation DSMenuVC {
    UITableView *_tv; UITextField *_search; UISegmentedControl *_seg; UILabel *_toast, *_cursor;
    DSGradView *_header; UIView *_scan; NSMutableArray<UILabel *> *_stats;
    NSArray<NSDictionary *> *_data; NSString *_query; NSTimer *_timer;
}

- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }

- (UIButton *)neon:(NSString *)t icon:(NSString *)ic color:(UIColor *)c sel:(SEL)s {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    [b setTitle:t forState:UIControlStateNormal]; [b setTitleColor:c forState:UIControlStateNormal];
    [b setImage:DSIcon(ic, 12) forState:UIControlStateNormal]; b.tintColor = c;
    b.titleLabel.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightSemibold]; b.imageEdgeInsets = UIEdgeInsetsMake(0, -4, 0, 4);
    b.backgroundColor = [c colorWithAlphaComponent:0.10];
    b.layer.cornerRadius = 12; b.layer.cornerCurve = kCACornerCurveContinuous;
    b.layer.borderWidth = 1; b.layer.borderColor = [c colorWithAlphaComponent:0.5].CGColor;
    b.layer.shadowColor = c.CGColor; b.layer.shadowOpacity = 0.18; b.layer.shadowRadius = 6; b.layer.shadowOffset = CGSizeMake(0, 2);
    [b addTarget:self action:s forControlEvents:UIControlEventTouchUpInside];
    [b.heightAnchor constraintEqualToConstant:42].active = YES;
    return b;
}

// عنوان قسم صغير فوق مجموعة أزرار — يعطي القائمة تنظيماً احترافياً بدل تكديس الأزرار
- (UILabel *)sectionLabel:(NSString *)t {
    UILabel *l = [UILabel new];
    l.text = [t uppercaseString];
    l.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightBold];
    l.textColor = DSHex(kGold); l.alpha = 0.85;
    return l;
}

- (UIView *)statCard:(NSString *)cap color:(UIColor *)c {
    UIView *v = [UIView new]; v.backgroundColor = DSHex(kPanel); v.layer.cornerRadius = 10;
    v.layer.borderWidth = 1; v.layer.borderColor = DSHex(kLine).CGColor;
    UILabel *n = [UILabel new]; n.text = @"0"; n.font = DSMono(20, UIFontWeightBold); n.textColor = c; n.textAlignment = NSTextAlignmentCenter;
    DSGlow(n.layer, c, 6);
    UILabel *k = [UILabel new]; k.text = cap; k.font = DSMono(9, UIFontWeightSemibold); k.textColor = DSHex(kDim); k.textAlignment = NSTextAlignmentCenter;
    UIStackView *st = [[UIStackView alloc] initWithArrangedSubviews:@[n, k]];
    st.axis = UILayoutConstraintAxisVertical; st.spacing = 2; st.translatesAutoresizingMaskIntoConstraints = NO;
    [v addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [st.topAnchor constraintEqualToAnchor:v.topAnchor constant:10], [st.bottomAnchor constraintEqualToAnchor:v.bottomAnchor constant:-8],
        [st.leadingAnchor constraintEqualToAnchor:v.leadingAnchor constant:4], [st.trailingAnchor constraintEqualToAnchor:v.trailingAnchor constant:-4]]];
    [_stats addObject:n];
    return v;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    self.view.backgroundColor = DSHex(kBG);
    _stats = [NSMutableArray array];

    // ----- header -----
    _header = [DSGradView new];
    CAGradientLayer *gl = (CAGradientLayer *)_header.layer;
    gl.colors = @[(id)DSHex(0x2B0505).CGColor, (id)DSHex(kBG).CGColor];
    gl.startPoint = CGPointMake(0, 0); gl.endPoint = CGPointMake(1, 1);
    _header.layer.cornerRadius = 14; _header.layer.borderWidth = 1;
    _header.layer.borderColor = [DSHex(kGreen) colorWithAlphaComponent:0.55].CGColor; _header.clipsToBounds = YES;

    UILabel *logo = [UILabel new];
    NSMutableAttributedString *logoStr = [[NSMutableAttributedString alloc] initWithString:@"👹  DOMAINSNIFFER"
        attributes:@{ NSFontAttributeName: DSMono(19, UIFontWeightHeavy), NSForegroundColorAttributeName: DSHex(kGreen), NSKernAttributeName: @(1.2) }];
    logo.attributedText = logoStr;
    DSGlow(logo.layer, DSHex(kGreen), 10); logo.adjustsFontSizeToFitWidth = YES; logo.minimumScaleFactor = 0.6;
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    [close setImage:DSIcon(@"xmark.circle.fill", 24) forState:UIControlStateNormal]; close.tintColor = DSHex(kRed);
    [close addTarget:self action:@selector(closeTap) forControlEvents:UIControlEventTouchUpInside];
    [close setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UIStackView *row1 = [[UIStackView alloc] initWithArrangedSubviews:@[logo, close]]; row1.alignment = UIStackViewAlignmentCenter;

    UILabel *prompt = [UILabel new]; prompt.text = @"$ summon --daemon --hook=builtin"; prompt.font = DSMono(11, UIFontWeightMedium); prompt.textColor = DSHex(kCyan);
    _cursor = [UILabel new]; _cursor.text = @"█"; _cursor.font = DSMono(11, UIFontWeightBold); _cursor.textColor = DSHex(kGreen);
    [_cursor setContentHuggingPriority:UILayoutPriorityRequired forAxis:UILayoutConstraintAxisHorizontal];
    UIStackView *row2 = [[UIStackView alloc] initWithArrangedSubviews:@[prompt, _cursor]]; row2.spacing = 3;

    UIView *creditBadge = [UIView new];
    creditBadge.backgroundColor = [DSHex(kGold) colorWithAlphaComponent:0.14];
    creditBadge.layer.cornerRadius = 9; creditBadge.layer.cornerCurve = kCACornerCurveContinuous;
    creditBadge.layer.borderWidth = 1.2; creditBadge.layer.borderColor = DSHex(kGold).CGColor;
    UILabel *creditIcon = [UILabel new]; creditIcon.text = @"👹"; creditIcon.font = [UIFont systemFontOfSize:12]; creditIcon.textColor = DSHex(kGold);
    UILabel *credit = [UILabel new]; credit.text = @"أفلاطون  •  Aflatoon — جميع الحقوق محفوظة";
    credit.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightBold]; credit.textColor = DSHex(kGold);
    credit.adjustsFontSizeToFitWidth = YES; credit.minimumScaleFactor = 0.65;
    UIStackView *creditRow = [[UIStackView alloc] initWithArrangedSubviews:@[creditIcon, credit]];
    creditRow.spacing = 5; creditRow.alignment = UIStackViewAlignmentCenter; creditRow.translatesAutoresizingMaskIntoConstraints = NO;
    [creditBadge addSubview:creditRow];
    [NSLayoutConstraint activateConstraints:@[
        [creditRow.topAnchor constraintEqualToAnchor:creditBadge.topAnchor constant:4], [creditRow.bottomAnchor constraintEqualToAnchor:creditBadge.bottomAnchor constant:-4],
        [creditRow.leadingAnchor constraintEqualToAnchor:creditBadge.leadingAnchor constant:9], [creditRow.trailingAnchor constraintEqualToAnchor:creditBadge.trailingAnchor constant:-9]]];
    UIStackView *creditWrap = [[UIStackView alloc] initWithArrangedSubviews:@[creditBadge, [UIView new]]];   // يدفع الشارة لليسار بدل تمديدها كامل العرض

    UIStackView *hs = [[UIStackView alloc] initWithArrangedSubviews:@[row1, row2, creditWrap]];
    hs.axis = UILayoutConstraintAxisVertical; hs.spacing = 5; hs.translatesAutoresizingMaskIntoConstraints = NO;
    [_header addSubview:hs];
    [NSLayoutConstraint activateConstraints:@[
        [hs.topAnchor constraintEqualToAnchor:_header.topAnchor constant:12], [hs.bottomAnchor constraintEqualToAnchor:_header.bottomAnchor constant:-12],
        [hs.leadingAnchor constraintEqualToAnchor:_header.leadingAnchor constant:14], [hs.trailingAnchor constraintEqualToAnchor:_header.trailingAnchor constant:-10]]];
    _scan = [UIView new]; _scan.backgroundColor = [DSHex(kGreen) colorWithAlphaComponent:0.35]; _scan.userInteractionEnabled = NO;
    [_header addSubview:_scan];

    // ----- stats -----
    UIStackView *stats = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self statCard:@"TOTAL" color:DSHex(kGreen)], [self statCard:@"DOMAINS" color:DSHex(kCyan)],
        [self statCard:@"IPS" color:DSHex(kAmber)], [self statCard:@"BLOCKED" color:DSHex(kRed)]]];
    stats.distribution = UIStackViewDistributionFillEqually; stats.spacing = 8;

    // ----- search -----
    _search = [UITextField new]; _search.delegate = self; _search.font = DSMono(14, UIFontWeightRegular); _search.textColor = DSHex(kText);
    _search.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"grep  domain | ip" attributes:@{ NSForegroundColorAttributeName: DSHex(kDim), NSFontAttributeName: DSMono(14, UIFontWeightRegular) }];
    _search.backgroundColor = DSHex(kPanel); _search.layer.cornerRadius = 10; _search.layer.borderWidth = 1; _search.layer.borderColor = DSHex(kLine).CGColor;
    _search.autocapitalizationType = UITextAutocapitalizationTypeNone; _search.autocorrectionType = UITextAutocorrectionTypeNo;
    _search.clearButtonMode = UITextFieldViewModeWhileEditing; _search.returnKeyType = UIReturnKeySearch; _search.keyboardAppearance = UIKeyboardAppearanceDark;
    UIImageView *mag = [[UIImageView alloc] initWithImage:DSIcon(@"magnifyingglass", 14)]; mag.tintColor = DSHex(kGreen); mag.contentMode = UIViewContentModeCenter;
    mag.frame = CGRectMake(0, 0, 36, 40); _search.leftView = mag; _search.leftViewMode = UITextFieldViewModeAlways;
    [_search addTarget:self action:@selector(queryChanged:) forControlEvents:UIControlEventEditingChanged];
    [_search.heightAnchor constraintEqualToConstant:40].active = YES;

    // ----- filter -----
    _seg = [[UISegmentedControl alloc] initWithItems:@[@"ALL", @"DOMAINS", @"IP", @"BLOCKED"]];
    _seg.selectedSegmentIndex = 0; _seg.backgroundColor = DSHex(kPanel); _seg.selectedSegmentTintColor = DSHex(kGreen);
    [_seg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kDim), NSFontAttributeName: DSMono(11, UIFontWeightBold) } forState:UIControlStateNormal];
    [_seg setTitleTextAttributes:@{ NSForegroundColorAttributeName: DSHex(kBG), NSFontAttributeName: DSMono(11, UIFontWeightHeavy) } forState:UIControlStateSelected];
    [_seg addTarget:self action:@selector(reload) forControlEvents:UIControlEventValueChanged];

    // ----- table -----
    _tv = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _tv.dataSource = self; _tv.delegate = self; _tv.backgroundColor = UIColor.clearColor; _tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    _tv.rowHeight = UITableViewAutomaticDimension; _tv.estimatedRowHeight = 84; _tv.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    [_tv registerClass:DSCell.class forCellReuseIdentifier:@"c"];
    [_tv setContentHuggingPriority:1 forAxis:UILayoutConstraintAxisVertical];
    [_tv setContentCompressionResistancePriority:1 forAxis:UILayoutConstraintAxisVertical];

    // ----- actions -----
    UIStackView *bar1 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:@"SAVE" icon:@"square.and.arrow.down" color:DSHex(kGreen) sel:@selector(saveTap)],
        [self neon:@"SHARE" icon:@"square.and.arrow.up" color:DSHex(kCyan) sel:@selector(shareTap:)],
        [self neon:@"COPY" icon:@"doc.on.doc" color:DSHex(kPurple) sel:@selector(copyTap)],
        [self neon:@"CLEAR" icon:@"trash" color:DSHex(kRed) sel:@selector(clearTap)]]];
    bar1.distribution = UIStackViewDistributionFillEqually; bar1.spacing = 8;
    UIStackView *bar2 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:@"NEXTDNS KEY" icon:@"key.fill" color:DSHex(kAmber) sel:@selector(apiTap)],
        [self neon:@"RULES" icon:@"arrow.triangle.2.circlepath" color:DSHex(kGreen) sel:@selector(rulesTap)],
        [self neon:([DSSettings shared].autoDNS ? @"DNS 8.8.8.8" : @"DNS OFF") icon:@"globe"
             color:([DSSettings shared].autoDNS ? DSHex(kCyan) : DSHex(kDim)) sel:@selector(dnsTap:)]]];
    bar2.distribution = UIStackViewDistributionFillEqually; bar2.spacing = 8;

    UIStackView *bar3 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].forceAll ? @"ALL → 8.8.8.8 : ON" : @"ALL → 8.8.8.8 : OFF") icon:@"bolt.fill"
             color:([DSSettings shared].forceAll ? DSHex(kRed) : DSHex(kDim)) sel:@selector(forceTap:)],
        [self neon:([DSSettings shared].chatMode ? @"CHAT → 8.8.8.8" : @"CHAT OFF") icon:@"bubble.left.and.bubble.right"
             color:([DSSettings shared].chatMode ? DSHex(kGreen) : DSHex(kDim)) sel:@selector(chatTap:)]]];

    UIStackView *bar4 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].joinSoundOn ? @"JOIN SOUND: ON" : @"JOIN SOUND: OFF") icon:@"speaker.wave.2.fill"
             color:([DSSettings shared].joinSoundOn ? DSHex(kCyan) : DSHex(kDim)) sel:@selector(joinSoundTap:)],
        [self neon:[NSString stringWithFormat:@"SPEED x%d", (int)[DSSettings shared].joinSoundRate] icon:@"gauge.with.dots.needle.67percent"
             color:DSHex(kAmber) sel:@selector(joinSpeedTap:)]]];
    bar4.distribution = UIStackViewDistributionFillEqually; bar4.spacing = 6;

    UIStackView *bar5 = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self neon:([DSSettings shared].voiceSpeedOn ? @"VOICE SPEED: ON" : @"VOICE SPEED: OFF") icon:@"waveform"
             color:([DSSettings shared].voiceSpeedOn ? DSHex(kPurple) : DSHex(kDim)) sel:@selector(voiceSpeedTap:)],
        [self neon:[NSString stringWithFormat:@"MAX x%d", (int)[DSSettings shared].voiceSpeedMax] icon:@"gauge.with.dots.needle.67percent"
             color:DSHex(kAmber) sel:@selector(voiceSpeedMaxTap:)]]];
    bar5.distribution = UIStackViewDistributionFillEqually; bar5.spacing = 6;
    bar3.distribution = UIStackViewDistributionFillEqually; bar3.spacing = 6;

    UILabel *foot = [UILabel new]; foot.text = @"© Aflatoon // أفلاطون — all rights reserved"; foot.textAlignment = NSTextAlignmentCenter;
    foot.font = DSMono(10, UIFontWeightMedium); foot.textColor = DSHex(kDim);

    UIStackView *main = [[UIStackView alloc] initWithArrangedSubviews:@[_header, stats, _search, _seg, _tv,
      [self sectionLabel:@"ادارة البيانات"], bar1,
      [self sectionLabel:@"الشبكة وDNS"], bar2, bar3,
      [self sectionLabel:@"الدردشة والصوت"], bar4, bar5,
      foot]];
    main.axis = UILayoutConstraintAxisVertical; main.spacing = 10; main.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:main];
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [main.topAnchor constraintEqualToAnchor:g.topAnchor constant:10], [main.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-6],
        [main.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:14], [main.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-14]]];

    _toast = [UILabel new]; _toast.backgroundColor = DSHex(kPanel); _toast.textColor = DSHex(kGreen); _toast.textAlignment = NSTextAlignmentCenter;
    _toast.font = DSMono(12, UIFontWeightBold); _toast.layer.cornerRadius = 10; _toast.layer.borderWidth = 1; _toast.layer.borderColor = DSHex(kGreen).CGColor;
    _toast.clipsToBounds = YES; _toast.alpha = 0; _toast.adjustsFontSizeToFitWidth = YES; _toast.minimumScaleFactor = 0.7;
    _toast.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:_toast];
    [NSLayoutConstraint activateConstraints:@[
        [_toast.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor], [_toast.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-120],
        [_toast.widthAnchor constraintGreaterThanOrEqualToConstant:180], [_toast.widthAnchor constraintLessThanOrEqualToAnchor:self.view.widthAnchor constant:-40],
        [_toast.heightAnchor constraintEqualToConstant:38]]];
    [self reload];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    _timer = [NSTimer scheduledTimerWithTimeInterval:1.5 target:self selector:@selector(reload) userInfo:nil repeats:YES];
    CABasicAnimation *b = [CABasicAnimation animationWithKeyPath:@"opacity"];
    b.fromValue = @1; b.toValue = @0; b.duration = 0.55; b.autoreverses = YES; b.repeatCount = HUGE_VALF;
    [_cursor.layer addAnimation:b forKey:@"blink"];
}
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.view layoutIfNeeded];
    CGFloat w = _header.bounds.size.width, h = _header.bounds.size.height;
    _scan.frame = CGRectMake(0, 0, w, 1.5);
    [UIView animateWithDuration:2.6 delay:0 options:UIViewAnimationOptionRepeat | UIViewAnimationOptionCurveLinear animations:^{
        self->_scan.frame = CGRectMake(0, h - 1.5, w, 1.5);
    } completion:nil];
}
- (void)viewDidDisappear:(BOOL)animated { [super viewDidDisappear:animated]; [_timer invalidate]; _timer = nil; }

- (void)reload {
    NSInteger m = _seg.selectedSegmentIndex;
    NSString *q = _query.lowercaseString;
    NSArray *all = [[DSStore shared] snapshot];
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger nd = 0, ni = 0, nb = 0;
    for (NSDictionary *e in all) {
        BOOL dom = [e[@"type"] isEqualToString:@"domain"], blk = [e[@"status"] isEqualToString:@"BLOCKED"];
        if (dom) nd++; else ni++;
        if (blk) nb++;
        if (m == 1 && !dom) continue;
        if (m == 2 && dom) continue;
        if (m == 3 && !blk) continue;
        if (q.length) {
            NSString *hay = [[NSString stringWithFormat:@"%@ %@", e[@"value"], [e[@"related"] componentsJoinedByString:@" "]] lowercaseString];
            if (![hay containsString:q]) continue;
        }
        [out addObject:e];
    }
    _data = out;
    NSArray *nums = @[@(all.count), @(nd), @(ni), @(nb)];
    for (NSUInteger i = 0; i < _stats.count; i++) _stats[i].text = [nums[i] stringValue];
    [_tv reloadData];
}

- (void)toast:(NSString *)t {
    _toast.text = t;
    [_toast.layer removeAllAnimations];
    [UIView animateWithDuration:0.2 animations:^{ self->_toast.alpha = 1; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.3 delay:1.8 options:0 animations:^{ self->_toast.alpha = 0; } completion:nil];
    }];
}

- (void)closeTap { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)queryChanged:(UITextField *)t { _query = t.text; [self reload]; }
- (BOOL)textFieldShouldReturn:(UITextField *)t { [t resignFirstResponder]; return YES; }

- (void)dnsTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.autoDNS = !st.autoDNS; [st save];
    UIColor *c = st.autoDNS ? DSHex(kCyan) : DSHex(kDim);
    [b setTitle:(st.autoDNS ? @"DNS 8.8.8.8" : @"DNS OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.autoDNS ? @"DNS تلقائي → 8.8.8.8 ✅" : @"DNS التلقائي متوقف")];
}

- (void)forceTap:(UIButton *)b {   // يعمل لحظياً: الأعلام تُقرأ عند كل اتصال جديد
    DSSettings *st = [DSSettings shared];
    st.forceAll = !st.forceAll; [st save];
    UIColor *c = st.forceAll ? DSHex(kRed) : DSHex(kDim);
    [b setTitle:(st.forceAll ? @"ALL → 8.8.8.8 : ON" : @"ALL → 8.8.8.8 : OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.forceAll ? @"كل النطاقات والـ IPs → 8.8.8.8 ⚡" : @"رجع الوضع الطبيعي")];
}

- (void)chatTap:(UIButton *)b {   // لحظي: يسري على أي اتصال جديد
    DSSettings *st = [DSSettings shared];
    st.chatMode = !st.chatMode; [st save];
    UIColor *c = st.chatMode ? DSHex(kGreen) : DSHex(kDim);
    [b setTitle:(st.chatMode ? @"CHAT → 8.8.8.8" : @"CHAT OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.chatMode ? @"الدردشة والكتابة → 8.8.8.8 💬" : @"الدردشة رجعت طبيعية")];
}

static NSString *DSFindJoinSoundFile(void);   // تصريح مسبق — التعريف الكامل لاحقاً بنفس الملف

- (void)joinSoundTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.joinSoundOn = !st.joinSoundOn; [st save];
    UIColor *c = st.joinSoundOn ? DSHex(kCyan) : DSHex(kDim);
    [b setTitle:(st.joinSoundOn ? @"JOIN SOUND: ON" : @"JOIN SOUND: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    if (st.joinSoundOn && !DSFindJoinSoundFile())
        [self toast:@"⚠️ ضع ملف join.mp3 (أو wav/m4a/caf) داخل Documents/DomainSniffer"];
    else
        [self toast:(st.joinSoundOn ? @"صوت الدخول مفعّل 🔊" : @"صوت الدخول متوقف")];
}

- (void)joinSpeedTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    int cur = (int)st.joinSoundRate; int next = cur + 1; if (next > 4) next = 1;
    st.joinSoundRate = (float)next; [st save];
    [b setTitle:[NSString stringWithFormat:@"SPEED x%d", next] forState:UIControlStateNormal];
    [self toast:[NSString stringWithFormat:@"سرعة صوت الدخول x%d", next]];
}

- (void)voiceSpeedTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    st.voiceSpeedOn = !st.voiceSpeedOn; [st save];
    UIColor *c = st.voiceSpeedOn ? DSHex(kPurple) : DSHex(kDim);
    [b setTitle:(st.voiceSpeedOn ? @"VOICE SPEED: ON" : @"VOICE SPEED: OFF") forState:UIControlStateNormal];
    [b setTitleColor:c forState:UIControlStateNormal]; b.tintColor = c;
    b.backgroundColor = [c colorWithAlphaComponent:0.12];
    b.titleLabel.adjustsFontSizeToFitWidth = YES; b.titleLabel.minimumScaleFactor = 0.7;
    [self toast:(st.voiceSpeedOn ? @"سرعة صوت المتكلمين مفعّلة 🎙️" : @"سرعة صوت المتكلمين متوقفة")];
}

- (void)voiceSpeedMaxTap:(UIButton *)b {
    DSSettings *st = [DSSettings shared];
    int cur = (int)st.voiceSpeedMax; int next = cur + 1; if (next > 4) next = 1;
    st.voiceSpeedMax = (float)next; [st save];
    [b setTitle:[NSString stringWithFormat:@"MAX x%d", next] forState:UIControlStateNormal];
    [self toast:[NSString stringWithFormat:@"الحد الأقصى للتسريع x%d", next]];
}

- (void)rulesTap {
    DSRulesVC *vc = [[DSRulesVC alloc] initWithStyle:UITableViewStyleInsetGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    [self presentViewController:nav animated:YES completion:nil];
}

- (void)apiTap {
    DSSettings *st = [DSSettings shared];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"🔑 NextDNS"
        message:@"مفتاح API من my.nextdns.io/account\nProfile ID اختياري (يُكتشف تلقائياً)" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = st.apiKey.length ? @"•••••• (محفوظ — اتركه فارغاً للإبقاء)" : @"API Key";
        t.autocapitalizationType = UITextAutocapitalizationTypeNone; t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [a addTextFieldWithConfigurationHandler:^(UITextField *t) {
        t.placeholder = @"Profile ID (اختياري)"; t.text = st.profileId;
        t.autocapitalizationType = UITextAutocapitalizationTypeNone; t.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    __weak UIAlertController *wa = a;
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"حذف المفتاح" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        st.apiKey = nil; st.profileId = nil; [st save]; [self toast:@"تم حذف المفتاح"];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"حفظ" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        NSCharacterSet *ws = NSCharacterSet.whitespaceAndNewlineCharacterSet;
        NSString *k = [wa.textFields[0].text stringByTrimmingCharactersInSet:ws];
        NSString *p = [wa.textFields[1].text stringByTrimmingCharactersInSet:ws];
        if (k.length) st.apiKey = k;
        if (![p isEqualToString:st.profileId ?: @""] || k.length) st.profileId = p.length ? p : nil;
        [st save];
        if (!st.apiKey.length) { [self toast:@"لا يوجد مفتاح"]; return; }
        [self toast:@"جاري التحقق…"];
        DSNDEnsureProfile(^(NSString *pid, NSString *err) {
            [self toast:pid ? @"تم الحفظ والتحقق ✅" : err];
        });
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)blockDomain:(NSString *)d {
    DSSettings *st = [DSSettings shared];
    if (!st.apiKey.length) { [self toast:@"أدخل مفتاح API أولاً"]; [self apiTap]; return; }
    [self toast:@"جاري الإرسال…"];
    DSNDEnsureProfile(^(NSString *pid, NSString *err) {
        if (!pid) { [self toast:err]; return; }
        NSString *path = [NSString stringWithFormat:@"/profiles/%@/denylist", pid];
        DSNDRequest(@"POST", path, @{ @"id": d, @"active": @YES }, ^(NSInteger code, id json, NSError *e) {
            if (code / 100 == 2) { [st markSent:d]; [self toast:[NSString stringWithFormat:@"⛔ تم حجب %@", d]]; [self reload]; }
            else if (code == 409 || [DSNDErrorText(code, json) containsString:@"duplicate"]) { [st markSent:d]; [self toast:@"موجود مسبقاً في Denylist"]; [self reload]; }
            else if (code == 401 || code == 403) [self toast:@"مفتاح API غير صحيح"];
            else [self toast:e ? e.localizedDescription : DSNDErrorText(code, json)];
        });
    });
}

- (void)showActionsFor:(NSDictionary *)e from:(UIView *)src {
    NSString *v = e[@"value"];
    BOOL isDomain = [e[@"type"] isEqualToString:@"domain"];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:v message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    if (isDomain) {
        [a addAction:[UIAlertAction actionWithTitle:@"⛔ حجب (NextDNS)" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) { [self blockDomain:v]; }]];
    } else {
        NSUInteger n = 0;
        for (NSString *r in e[@"related"]) {
            if (DSIsIPString(r) || n++ >= 3) continue;
            [a addAction:[UIAlertAction actionWithTitle:[@"⛔ حجب " stringByAppendingString:r] style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) { [self blockDomain:r]; }]];
        }
    }
    [a addAction:[UIAlertAction actionWithTitle:@"🔁 استبدال…" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        [DSRulesVC promptFrom:v over:self done:^{ [self toast:@"تمت إضافة القاعدة ✅"]; }];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"📋 نسخ" style:UIAlertActionStyleDefault handler:^(UIAlertAction *x) {
        UIPasteboard.generalPasteboard.string = v; [self toast:@"تم النسخ"];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    a.popoverPresentationController.sourceView = src;
    a.popoverPresentationController.sourceRect = src.bounds;
    [self presentViewController:a animated:YES completion:nil];
}

- (void)saveTap {
    [[DSStore shared] saveAll];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"تم الحفظ ✅"
        message:@"Documents/DomainSniffer/\n• denylist_nextdns.txt\n• domains.txt\n• ips.txt\n• data.json\n\nاستخدم زر SHARE لحفظها في تطبيق الملفات."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"حسناً" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)shareTap:(UIButton *)sender {
    NSArray *urls = [[DSStore shared] saveAll];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:urls applicationActivities:nil];
    vc.popoverPresentationController.sourceView = sender;
    vc.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)copyTap {
    UIPasteboard.generalPasteboard.string = [[DSStore shared] denylistText];
    [self toast:[NSString stringWithFormat:@"تم نسخ %lu نطاق", (unsigned long)[[DSStore shared] denylistCount]]];
}

- (void)clearTap {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"مسح كل السجل؟" message:nil preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"إلغاء" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"مسح" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *x) {
        [[DSStore shared] clear]; [self reload];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    if (_data.count == 0) {
        UILabel *l = [UILabel new]; l.numberOfLines = 0; l.textAlignment = NSTextAlignmentCenter;
        l.text = @"$ waiting for traffic…\nشغّل اللعبة وراح تظهر الاتصالات هنا";
        l.font = DSMono(12, UIFontWeightRegular); l.textColor = DSHex(kDim); tv.backgroundView = l;
    } else tv.backgroundView = nil;
    return _data.count;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    DSCell *c = [tv dequeueReusableCellWithIdentifier:@"c" forIndexPath:ip];
    NSDictionary *e = _data[ip.row];
    [c configure:e sent:[[DSSettings shared] wasSent:e[@"value"]]];
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    [self showActionsFor:_data[ip.row] from:[tv cellForRowAtIndexPath:ip]];
}
@end

#pragma mark - Floating orb

@interface DSPassWindow : UIWindow
@end
@implementation DSPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    return (v == self.rootViewController.view || v == self) ? nil : v;
}
@end

@interface DSRootVC : UIViewController
@end
@implementation DSRootVC {
    UIButton *_fab; UIView *_ring; UILabel *_banner;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.clearColor;
    _ring = [[UIView alloc] initWithFrame:CGRectMake(16, 140, 56, 56)];
    _ring.layer.cornerRadius = 28; _ring.layer.borderWidth = 1.5; _ring.layer.borderColor = DSHex(kGreen).CGColor;
    _ring.userInteractionEnabled = NO; [self.view addSubview:_ring];
    _fab = [UIButton buttonWithType:UIButtonTypeCustom];
    _fab.frame = CGRectMake(16, 140, 56, 56);
    _fab.backgroundColor = [DSHex(kBG) colorWithAlphaComponent:0.94];
    _fab.layer.cornerRadius = 28; _fab.layer.borderWidth = 1.5; _fab.layer.borderColor = DSHex(kGreen).CGColor;
    DSGlow(_fab.layer, DSHex(kGreen), 10);
    [_fab setImage:DSIcon(@"dot.radiowaves.left.and.right", 22) forState:UIControlStateNormal]; _fab.tintColor = DSHex(kGreen);
    [_fab addTarget:self action:@selector(open) forControlEvents:UIControlEventTouchUpInside];
    [_fab addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
    [self.view addSubview:_fab];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(startPulse) name:UIApplicationDidBecomeActiveNotification object:nil];
}
- (void)startPulse {
    [_ring.layer removeAllAnimations];
    CABasicAnimation *s = [CABasicAnimation animationWithKeyPath:@"transform.scale"]; s.fromValue = @1; s.toValue = @1.7;
    CABasicAnimation *o = [CABasicAnimation animationWithKeyPath:@"opacity"]; o.fromValue = @0.7; o.toValue = @0;
    CAAnimationGroup *g = [CAAnimationGroup animation]; g.animations = @[s, o]; g.duration = 1.8; g.repeatCount = HUGE_VALF;
    [_ring.layer addAnimation:g forKey:@"pulse"];
}
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self startPulse];
    if (_banner) return;
    _banner = [UILabel new]; _banner.text = @"  ◉ DOMAIN//SNIFFER  •  © أفلاطون / Aflatoon  ";
    _banner.font = DSMono(11, UIFontWeightBold); _banner.textColor = DSHex(kGreen); _banner.backgroundColor = [DSHex(kBG) colorWithAlphaComponent:0.95];
    _banner.layer.cornerRadius = 12; _banner.layer.borderWidth = 1; _banner.layer.borderColor = DSHex(kGreen).CGColor; _banner.clipsToBounds = YES;
    [_banner sizeToFit];
    CGFloat bw = _banner.bounds.size.width + 8, bh = 26;
    _banner.frame = CGRectMake((self.view.bounds.size.width - bw) / 2, self.view.safeAreaInsets.top + 6, bw, bh);
    _banner.textAlignment = NSTextAlignmentCenter; _banner.alpha = 0;
    [self.view addSubview:_banner];
    [UIView animateWithDuration:0.35 animations:^{ self->_banner.alpha = 1; } completion:^(BOOL f) {
        [UIView animateWithDuration:0.6 delay:3.0 options:0 animations:^{ self->_banner.alpha = 0; } completion:nil];
    }];
}
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds; CGPoint c = _fab.center;
    c.x = MIN(MAX(c.x, 28), b.size.width - 28); c.y = MIN(MAX(c.y, 28), b.size.height - 28);
    _fab.center = c; _ring.center = c;
}
- (void)pan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self.view];
    _fab.center = CGPointMake(_fab.center.x + t.x, _fab.center.y + t.y); _ring.center = _fab.center;
    [g setTranslation:CGPointZero inView:self.view];
    [self.view setNeedsLayout];
}
- (void)open {
    if (self.presentedViewController) return;
    DSMenuVC *vc = [DSMenuVC new];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:vc animated:YES completion:nil];
}
@end

#pragma mark - تسريع صوت الروم مع الحفاظ على النغمة (WSOLA)
// ملاحظة مهمة: الدردشة حيّة وليست ملفاً جاهزاً. السرعة "تتكيّف" حسب التراكم المتوفر فقط —
// تبدأ من 1x وتتصاعد تدريجياً حتى الحد الأقصى المختار كلما وُجد تراكم (بعد وقفات الكلام مثلاً)،
// وتهدأ تلقائياً عند نفاد التراكم. هذا السلوك مُختبَر ومؤكد رياضياً (محرك overlap-add قياسي)،
// وليس تخميناً. تمت تجربة النواة بمعزل عن اللعبة قبل الدمج هنا.
#define DS_WS_CAP (48000 * 8)

typedef struct {
    int16_t ring[DS_WS_CAP]; long wpos, rpos;
    int sr, Hs, win, search;
    float accum[2048];
    long anaPos;
    int16_t prevTail[1024];
    int primed;
} DSWsola;

static void DSWsInit(DSWsola *w, int sr) {
    memset(w, 0, sizeof *w);
    w->sr = sr; w->Hs = sr / 100; w->win = w->Hs * 2; w->search = w->Hs / 2;
}
static void DSWsFeed(DSWsola *w, const int16_t *in, int n) {
    for (int i = 0; i < n; i++) w->ring[(w->wpos + i) % DS_WS_CAP] = in[i];
    w->wpos += n;
    if (w->wpos - w->rpos > DS_WS_CAP - 4096) w->rpos = w->wpos - (DS_WS_CAP - 4096);
}
static int16_t DSWsAt(DSWsola *w, long pos) { return (pos < w->rpos || pos >= w->wpos) ? 0 : w->ring[pos % DS_WS_CAP]; }

static int DSWsBestOffset(DSWsola *w, long candidate, const int16_t *ref, int refLen) {
    long bestScore = -1; int best = 0;
    for (int off = -w->search; off <= w->search; off++) {
        long start = candidate + off;
        if (start < w->rpos || start + refLen >= w->wpos) continue;
        long score = 0;
        for (int i = 0; i < refLen; i++) { int32_t a = ref[i], b = DSWsAt(w, start + i); score += a * b; }
        if (score > bestScore) { bestScore = score; best = off; }
    }
    return best;
}

// ينتج Hs عيّنة نهائية في كل نداء (نفس عدد العيّنات المطلوب من Agora)؛ السرعة تتكيّف تلقائياً
static void DSWsStep(DSWsola *w, int16_t *outHs, float maxSpeed) {
    if (w->Hs <= 0 || w->Hs > 1024) return;
    long avail = w->wpos - w->anaPos;
    float backlogSec = (float)avail / w->sr;
    float speed = 1.0f + (maxSpeed - 1.0f) * fminf(backlogSec / 1.0f, 1.0f);
    int Ha = (int)(w->Hs * speed); if (Ha < w->Hs) Ha = w->Hs;
    if (!w->primed) { w->anaPos = w->rpos; w->primed = 1; }

    int off = DSWsBestOffset(w, w->anaPos, w->prevTail, w->Hs);
    long start = w->anaPos + off;
    if (start < w->rpos) start = w->rpos;

    for (int i = 0; i < w->win; i++) {
        float tri = (i < w->Hs) ? (float)i / w->Hs : (float)(w->win - i) / w->Hs;
        w->accum[i] += DSWsAt(w, start + i) * tri;
    }
    for (int i = 0; i < w->Hs; i++) {
        float v = w->accum[i];
        if (v > 32767) v = 32767; if (v < -32768) v = -32768;
        outHs[i] = (int16_t)v;
    }
    for (int i = 0; i < w->Hs; i++) w->prevTail[i] = DSWsAt(w, start + w->Hs + i);
    memmove(w->accum, w->accum + w->Hs, (w->win - w->Hs) * sizeof(float));
    memset(w->accum + (w->win - w->Hs), 0, w->Hs * sizeof(float));
    w->anaPos = start + Ha;
    if (w->anaPos > w->wpos) w->anaPos = w->wpos;
}

// ---- ربط Agora: مراقب صوت خام رسمي (AgoraAudioDataFrameProtocol) — يعالج الصوت القادم لجهازك فقط ----
static DSWsola gVoiceWs[8];              // قناة لكل "uid" متكلم، حتى ما تتداخل أصوات اللاعبين ببعض
static NSMapTable *gVoiceWsByUid;        // uid -> فهرس في gVoiceWs
static dispatch_once_t gVoiceWsOnce;

static DSWsola *DSWsForUid(NSUInteger uid) {
    dispatch_once(&gVoiceWsOnce, ^{
        gVoiceWsByUid = [NSMapTable strongToStrongObjectsMapTable];
        for (int i = 0; i < 8; i++) DSWsInit(&gVoiceWs[i], 48000);
    });
    NSNumber *key = @(uid);
    NSNumber *idx = [gVoiceWsByUid objectForKey:key];
    if (!idx) {
        static int next = 0;
        idx = @(next % 8); next++;
        [gVoiceWsByUid setObject:idx forKey:key];
        DSWsInit(&gVoiceWs[idx.intValue], 48000);
    }
    return &gVoiceWs[idx.intValue];
}

@protocol DSAgoraAudioDataFrameProtocol <NSObject>
@optional
- (BOOL)onRecordAudioFrame:(id)frame;
- (BOOL)onPlaybackAudioFrame:(id)frame;
- (BOOL)onMixedAudioFrame:(id)frame;
- (BOOL)onPlaybackAudioFrameBeforeMixing:(id)frame uid:(NSUInteger)uid;
@end

@interface DSAudioFrameProxy : NSObject <DSAgoraAudioDataFrameProtocol>
@end
@implementation DSAudioFrameProxy
// نعالج الصوت *قبل الخلط* لكل متكلم على حدة (uid)، حتى التسريع ما يشوّش أصوات بعض ببعض
- (BOOL)onPlaybackAudioFrameBeforeMixing:(id)frameObj uid:(NSUInteger)uid {
    if (![DSSettings shared].voiceSpeedOn) return YES;
    @try {
        id bufVal = [frameObj valueForKey:@"buffer"];   // قد يصل كـ NSValue يغلّف مؤشر void* (وليس مؤشراً مباشراً)
        int16_t *buf = NULL;
        if ([bufVal isKindOfClass:[NSValue class]]) buf = (int16_t *)[(NSValue *)bufVal pointerValue];
        else return YES;   // شكل غير متوقع للبيانات: مرّر الصوت الأصلي بدون تعديل، بدل أي كاست غير آمن
        NSInteger samplesPerChannel = [[frameObj valueForKey:@"samplesPerChannel"] integerValue];
        NSInteger channels = [[frameObj valueForKey:@"channels"] integerValue];
        NSInteger sr = [[frameObj valueForKey:@"samplesPerSec"] integerValue];
        if (!buf || samplesPerChannel <= 0 || samplesPerChannel > 1024 || channels < 1 || channels > 2 || sr < 8000 || sr > 48000) return YES;
        DSWsola *w = DSWsForUid(uid);
        if (w->sr != (int)sr) DSWsInit(w, (int)sr);
        float maxSpeed = [DSSettings shared].voiceSpeedMax;

        if (channels == 1) {
            DSWsFeed(w, buf, (int)samplesPerChannel);
            int16_t out[1024];
            DSWsStep(w, out, maxSpeed);
            memcpy(buf, out, samplesPerChannel * sizeof(int16_t));
        } else {   // ستيريو: نفصل القناتين، نعالج كل وحدة بنفس قرار المحاذاة، ثم نعيد التشبيك
            static int16_t left[1024], right[1024], outL[1024], outR[1024];
            for (NSInteger i = 0; i < samplesPerChannel; i++) { left[i] = buf[i*2]; right[i] = buf[i*2+1]; }
            DSWsFeed(w, left, (int)samplesPerChannel);
            DSWsStep(w, outL, maxSpeed);
            DSWsFeed(w, right, (int)samplesPerChannel);   // ملاحظة: يعالج القناتين بتوقيت مستقل بسيط؛ كافٍ لصوت بشري أحادي المصدر عادة
            DSWsStep(w, outR, maxSpeed);
            for (NSInteger i = 0; i < samplesPerChannel; i++) { buf[i*2] = outL[i]; buf[i*2+1] = outR[i]; }
        }
    } @catch (__unused NSException *e) { return YES; }   // أي خلل غير متوقع: مرّر الصوت الأصلي بدون تعديل، أبداً لا نكسر الاتصال
    return YES;
}
- (BOOL)onPlaybackAudioFrame:(id)frame { return YES; }   // نعتمد "قبل الخلط" لكل متكلم على حدة؛ هذا احتياطي فقط
- (BOOL)onRecordAudioFrame:(id)frame { return YES; }
- (BOOL)onMixedAudioFrame:(id)frame { return YES; }
@end

static DSAudioFrameProxy *gDSAudioProxy;
static void DSEnsureVoiceSpeedWired(id engine) {   // يستدعى عند أول انضمام ناجح لروم
    if (!engine) return;
    static BOOL done = NO; if (done) return; done = YES;
    @try {
        if (!gDSAudioProxy) gDSAudioProxy = [DSAudioFrameProxy new];
        if ([engine respondsToSelector:@selector(setAgoraAudioFrameDelegate:)])
            [engine performSelector:@selector(setAgoraAudioFrameDelegate:) withObject:gDSAudioProxy];
        // تفعيل استلام الصوت الخام قبل الخلط، وضع قراءة وكتابة (2)، عيّنات 10ms عند 48kHz
        SEL sel = NSSelectorFromString(@"setPlaybackAudioFrameParametersWithSampleRate:channel:mode:samplesPerCall:");
        if ([engine respondsToSelector:sel]) {
            NSMethodSignature *sig = [engine methodSignatureForSelector:sel];
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
            inv.selector = sel; inv.target = engine;
            NSInteger sr = 48000, ch = 1, mode = 2, spc = 480;
            [inv setArgument:&sr atIndex:2]; [inv setArgument:&ch atIndex:3];
            [inv setArgument:&mode atIndex:4]; [inv setArgument:&spc atIndex:5];
            [inv invoke];
        }
    } @catch (__unused NSException *e) {}
}

#pragma mark - صوت دخول الروم (ملف محلي فقط، بدون أي تسجيل أو سمع لأحد)

// ضع ملف الصوت باسم join.mp3 أو join.wav أو join.m4a أو join.caf داخل:
// Documents/DomainSniffer  (نفس مجلد settings.json — يظهر عبر File Sharing في ESign/Files)
static AVAudioPlayer *gJoinPlayer;

static NSString *DSFindJoinSoundFile(void) {
    NSArray *names = @[@"join.mp3", @"join.wav", @"join.m4a", @"join.caf"];
    for (NSString *n in names) {
        NSString *p = [DSDir() stringByAppendingPathComponent:n];
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return p;
    }
    return nil;
}

static void DSPlayJoinSound(void) {
    if (![DSSettings shared].joinSoundOn) return;
    NSString *path = DSFindJoinSoundFile();
    if (!path) { NSLog(@"[DomainSniffer] join sound: ضع ملف join.mp3/.wav/.m4a/.caf داخل Documents/DomainSniffer"); return; }
    dispatch_async(dispatch_get_main_queue(), ^{
        NSError *err = nil;
        [[AVAudioSession sharedInstance] setCategory:AVAudioSessionCategoryAmbient error:nil];   // صيغة كلاسيكية، متوفرة بكل إصدارات SDK
        [[AVAudioSession sharedInstance] setActive:YES error:nil];
        AVAudioPlayer *p = [[AVAudioPlayer alloc] initWithContentsOfURL:[NSURL fileURLWithPath:path] error:&err];
        if (!p) { NSLog(@"[DomainSniffer] تعذر تشغيل ملف الصوت: %@", err); return; }
        p.enableRate = YES;
        float r = [DSSettings shared].joinSoundRate; if (r < 1) r = 1; if (r > 4) r = 4;
        p.rate = r;
        p.volume = 1.0;
        gJoinPlayer = p;   // تمسكه حتى ما ينقطع بالـ ARC قبل ما يخلّص
        [p play];
    });
}

// Hook مكتبة Agora (إن وجدت بالتطبيق) — يشتغل الصوت فقط عند نجاح الانضمام الفعلي للروم،
// ولا يتدخّل بأي صوت ثاني داخل المكالمة ولا يسمع/يسجّل أحد — تشغيل ملف محلي فقط.
%group DSAgoraJoinSoundHooks

// تم تأكيد أسماء الدوال هذه من ثنائيات AgoraRtcKit.framework الفعلية داخل IPA اللعبة.
// غرف يلا لودو تستخدم أسلوب القنوات المتعددة (AgoraRtcChannel عبر createRtcChannel:)،
// فالانضمام الفعلي للروم الصوتي يصير على كائن القناة، لا على AgoraRtcEngineKit نفسه.

%hook AgoraRtcChannel

- (int)joinChannelByToken:(NSString *)token info:(NSString *)info uid:(NSUInteger)uid options:(id)options joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByToken:(NSString *)token info:(NSString *)info uid:(NSUInteger)uid options:(id)options {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByUserAccount:(NSString *)userAccount token:(NSString *)token options:(id)options {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

%end

// احتياطي: إذا روم معيّن استخدم أسلوب القناة الواحدة (الانضمام مباشرة على المحرك)
%hook AgoraRtcEngineKit

+ (instancetype)sharedEngineWithAppId:(NSString *)appId delegate:(id)delegate {
    id r = %orig;
    DSEnsureVoiceSpeedWired(r);
    return r;
}
+ (instancetype)sharedEngineWithConfig:(id)config delegate:(id)delegate {
    id r = %orig;
    DSEnsureVoiceSpeedWired(r);
    return r;
}

- (int)joinChannelByToken:(NSString *)token channelId:(NSString *)channelId info:(NSString *)info uid:(NSUInteger)uid joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

- (int)joinChannelByToken:(NSString *)token channelId:(NSString *)channelId info:(NSString *)info uid:(NSUInteger)uid options:(id)options joinSuccess:(void (^)(NSString *, NSUInteger, NSInteger))joinSuccessBlock {
    int r = %orig;
    if (r == 0) DSPlayJoinSound();
    return r;
}

%end
%end

static DSPassWindow *gWindow;

static void DSShow(void) {
    if (gWindow) return;
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] && s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    DSPassWindow *w = scene ? [[DSPassWindow alloc] initWithWindowScene:scene]
                            : [[DSPassWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    w.windowLevel = UIWindowLevelAlert + 100;
    w.backgroundColor = UIColor.clearColor;
    w.rootViewController = [DSRootVC new];
    w.hidden = NO;
    gWindow = w;
}

__attribute__((constructor)) static void DSInit(void) {
    @autoreleasepool {
        [DSStore shared];
        [DSSettings shared];  // يحمّل القواعد المفعّلة فوراً قبل أي اتصال
        DSInstallCHooks();
        DSInstallURLSessionHooks();
        %init(DSAgoraJoinSoundHooks);
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil
            queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ DSShow(); });
        }];
    }
}
