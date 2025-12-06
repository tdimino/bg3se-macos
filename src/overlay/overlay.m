// overlay.m - In-game console overlay implementation
// NSWindow-based floating console with Tanit symbol

#import <Cocoa/Cocoa.h>
#import <QuartzCore/QuartzCore.h>
#include "overlay.h"
#include "../core/logging.h"

// Forward declarations
@class BG3SEOverlayWindow;
@class BG3SEOverlayView;
@class BG3SEConsoleView;

// ============================================================================
// Static State
// ============================================================================

static BG3SEOverlayWindow *s_overlay_window = nil;
static BG3SEConsoleView *s_console_view = nil;
static overlay_command_callback s_command_callback = NULL;
static bool s_initialized = false;

// Colors - Aldea Tanit warm amber/gold palette
#define OVERLAY_BG_COLOR [NSColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.94]
#define OVERLAY_BORDER_COLOR [NSColor colorWithRed:0.984 green:0.749 blue:0.141 alpha:0.6]
// Tanit colors: warm gold matching rgba(253,224,71) and rgba(251,191,36)
#define TANIT_PRIMARY [NSColor colorWithRed:0.992 green:0.878 blue:0.278 alpha:1.0]    // #FDE047
#define TANIT_SECONDARY [NSColor colorWithRed:0.984 green:0.749 blue:0.141 alpha:1.0]  // #FBBF24
#define TANIT_GLOW [NSColor colorWithRed:0.984 green:0.749 blue:0.141 alpha:0.4]
#define TEXT_COLOR [NSColor colorWithRed:0.92 green:0.92 blue:0.92 alpha:1.0]
#define INPUT_BG_COLOR [NSColor colorWithRed:0.12 green:0.12 blue:0.14 alpha:1.0]

// Dimensions
#define OVERLAY_WIDTH 700
#define OVERLAY_HEIGHT 400
#define TANIT_SIZE 36
#define BORDER_WIDTH 2
#define PADDING 12

// ============================================================================
// Tanit Symbol View - Draws the Symbol of Tanit
// ============================================================================

@interface BG3SETanitView : NSView
@end

@implementation BG3SETanitView

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.wantsLayer = YES;
        self.layer.backgroundColor = [NSColor clearColor].CGColor;

        // Add subtle pulsing glow animation
        [self addGlowAnimation];
    }
    return self;
}

- (void)addGlowAnimation {
    // Create a glow layer behind the symbol
    CALayer *glowLayer = [CALayer layer];
    glowLayer.frame = CGRectInset(self.bounds, -4, -4);
    glowLayer.cornerRadius = glowLayer.frame.size.width / 2;
    glowLayer.backgroundColor = [NSColor clearColor].CGColor;

    // Radial gradient glow effect
    CAGradientLayer *gradientLayer = [CAGradientLayer layer];
    gradientLayer.type = kCAGradientLayerRadial;
    gradientLayer.frame = glowLayer.bounds;
    gradientLayer.colors = @[
        (id)[NSColor colorWithRed:0.992 green:0.878 blue:0.278 alpha:0.5].CGColor,
        (id)[NSColor colorWithRed:0.984 green:0.749 blue:0.141 alpha:0.2].CGColor,
        (id)[NSColor clearColor].CGColor
    ];
    gradientLayer.locations = @[@0.0, @0.5, @1.0];
    gradientLayer.startPoint = CGPointMake(0.5, 0.5);
    gradientLayer.endPoint = CGPointMake(1.0, 1.0);

    [self.layer insertSublayer:gradientLayer atIndex:0];

    // Pulsing opacity animation
    CABasicAnimation *pulseAnim = [CABasicAnimation animationWithKeyPath:@"opacity"];
    pulseAnim.fromValue = @0.6;
    pulseAnim.toValue = @1.0;
    pulseAnim.duration = 2.0;
    pulseAnim.autoreverses = YES;
    pulseAnim.repeatCount = HUGE_VALF;
    pulseAnim.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
    [gradientLayer addAnimation:pulseAnim forKey:@"pulse"];
}

- (BOOL)isFlipped {
    return YES;
}

- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];

    CGContextRef ctx = [[NSGraphicsContext currentContext] CGContext];
    CGFloat w = self.bounds.size.width;
    CGFloat h = self.bounds.size.height;
    CGFloat cx = w / 2;

    // Scale factor for the symbol
    CGFloat scale = w / 40.0;

    // === Draw glow shadow first ===
    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0, 0), 8.0,
        [NSColor colorWithRed:0.984 green:0.749 blue:0.141 alpha:0.6].CGColor);

    // Set warm gold color matching Twilio-Aldea palette
    CGContextSetRGBFillColor(ctx, 0.992, 0.878, 0.278, 1.0);  // #FDE047
    CGContextSetRGBStrokeColor(ctx, 0.984, 0.749, 0.141, 1.0); // #FBBF24
    CGContextSetLineWidth(ctx, 2.0);

    // === Draw the Tanit Symbol ===

    // 1. Circle (disc/sun) - top center
    CGFloat circleRadius = 5 * scale;
    CGFloat circleY = 8 * scale;
    CGContextFillEllipseInRect(ctx, CGRectMake(cx - circleRadius, circleY - circleRadius,
                                                circleRadius * 2, circleRadius * 2));

    // 2. Crescent/horns - curved arms extending from sides of circle
    CGFloat hornY = circleY;
    CGFloat hornWidth = 8 * scale;
    CGFloat hornHeight = 4 * scale;

    // Left horn (crescent curve)
    CGContextBeginPath(ctx);
    CGContextMoveToPoint(ctx, cx - circleRadius - 1, hornY);
    CGContextAddQuadCurveToPoint(ctx, cx - circleRadius - hornWidth, hornY - hornHeight,
                                  cx - circleRadius - hornWidth * 1.5, hornY + hornHeight * 0.5);
    CGContextStrokePath(ctx);

    // Right horn (crescent curve)
    CGContextBeginPath(ctx);
    CGContextMoveToPoint(ctx, cx + circleRadius + 1, hornY);
    CGContextAddQuadCurveToPoint(ctx, cx + circleRadius + hornWidth, hornY - hornHeight,
                                  cx + circleRadius + hornWidth * 1.5, hornY + hornHeight * 0.5);
    CGContextStrokePath(ctx);

    // 3. Horizontal bar (arms) - below the circle
    CGFloat barY = circleY + circleRadius + 3 * scale;
    CGFloat barWidth = 14 * scale;
    CGFloat barHeight = 2 * scale;
    CGContextFillRect(ctx, CGRectMake(cx - barWidth, barY, barWidth * 2, barHeight));

    // 4. Triangular body - below the bar
    CGFloat triTop = barY + barHeight;
    CGFloat triBottom = h - 2 * scale;
    CGFloat triTopWidth = 6 * scale;
    CGFloat triBottomWidth = 12 * scale;

    CGContextBeginPath(ctx);
    CGContextMoveToPoint(ctx, cx - triTopWidth, triTop);
    CGContextAddLineToPoint(ctx, cx + triTopWidth, triTop);
    CGContextAddLineToPoint(ctx, cx + triBottomWidth, triBottom);
    CGContextAddLineToPoint(ctx, cx - triBottomWidth, triBottom);
    CGContextClosePath(ctx);
    CGContextFillPath(ctx);

    // 5. Bottom horizontal bar
    CGFloat bottomBarY = triBottom;
    CGFloat bottomBarWidth = 16 * scale;
    CGFloat bottomBarHeight = 2 * scale;
    CGContextFillRect(ctx, CGRectMake(cx - bottomBarWidth, bottomBarY,
                                       bottomBarWidth * 2, bottomBarHeight));

    CGContextRestoreGState(ctx);
}

@end

// ============================================================================
// Console View - Input field + Output text area
// ============================================================================

@interface BG3SEConsoleView : NSView <NSTextFieldDelegate>
@property (nonatomic, strong) NSScrollView *scrollView;
@property (nonatomic, strong) NSTextView *outputView;
@property (nonatomic, strong) NSTextField *inputField;
@property (nonatomic, strong) BG3SETanitView *tanitView;
@property (nonatomic, strong) NSMutableArray<NSString *> *commandHistory;
@property (nonatomic, assign) NSInteger historyIndex;
@end

@implementation BG3SEConsoleView

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.wantsLayer = YES;
        self.layer.backgroundColor = OVERLAY_BG_COLOR.CGColor;
        self.layer.borderColor = OVERLAY_BORDER_COLOR.CGColor;
        self.layer.borderWidth = BORDER_WIDTH;
        self.layer.cornerRadius = 8;

        _commandHistory = [NSMutableArray array];
        _historyIndex = -1;

        [self setupSubviews];
    }
    return self;
}

- (void)setupSubviews {
    CGFloat w = self.bounds.size.width;
    CGFloat h = self.bounds.size.height;

    // Tanit symbol in top-left corner
    _tanitView = [[BG3SETanitView alloc] initWithFrame:NSMakeRect(PADDING, PADDING, TANIT_SIZE, TANIT_SIZE)];
    [self addSubview:_tanitView];

    // Title label next to Tanit
    NSTextField *titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING + TANIT_SIZE + 8, PADDING + 8, 200, 20)];
    titleLabel.stringValue = @"BG3SE Console";
    titleLabel.font = [NSFont boldSystemFontOfSize:14];
    titleLabel.textColor = TANIT_PRIMARY;
    titleLabel.backgroundColor = [NSColor clearColor];
    titleLabel.bordered = NO;
    titleLabel.editable = NO;
    titleLabel.selectable = NO;
    [self addSubview:titleLabel];

    // Output text view (scrollable)
    CGFloat outputTop = PADDING + TANIT_SIZE + 8;
    CGFloat outputHeight = h - outputTop - 40 - PADDING;

    _scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(PADDING, outputTop, w - PADDING * 2, outputHeight)];
    _scrollView.hasVerticalScroller = YES;
    _scrollView.hasHorizontalScroller = NO;
    _scrollView.autohidesScrollers = YES;
    _scrollView.borderType = NSNoBorder;
    _scrollView.backgroundColor = [NSColor clearColor];

    _outputView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, w - PADDING * 2 - 15, outputHeight)];
    _outputView.backgroundColor = [NSColor clearColor];
    _outputView.textColor = TEXT_COLOR;
    _outputView.font = [NSFont fontWithName:@"Menlo" size:12];
    _outputView.editable = NO;
    _outputView.selectable = YES;
    _outputView.textContainerInset = NSMakeSize(4, 4);
    [_outputView setAutoresizingMask:NSViewWidthSizable];

    _scrollView.documentView = _outputView;
    [self addSubview:_scrollView];

    // Prompt label
    NSTextField *promptLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING, h - 32, 20, 24)];
    promptLabel.stringValue = @">";
    promptLabel.font = [NSFont fontWithName:@"Menlo-Bold" size:14];
    promptLabel.textColor = TANIT_PRIMARY;
    promptLabel.backgroundColor = [NSColor clearColor];
    promptLabel.bordered = NO;
    promptLabel.editable = NO;
    [self addSubview:promptLabel];

    // Input field
    _inputField = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING + 20, h - 34, w - PADDING * 2 - 20, 26)];
    _inputField.font = [NSFont fontWithName:@"Menlo" size:12];
    _inputField.textColor = TEXT_COLOR;
    _inputField.backgroundColor = INPUT_BG_COLOR;
    _inputField.bordered = NO;
    _inputField.focusRingType = NSFocusRingTypeNone;
    _inputField.placeholderString = @"Enter Lua command...";
    _inputField.delegate = self;
    _inputField.wantsLayer = YES;
    _inputField.layer.cornerRadius = 4;
    [self addSubview:_inputField];
}

- (BOOL)isFlipped {
    return YES;
}

- (void)appendOutput:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSAttributedString *attrStr = [[NSAttributedString alloc]
            initWithString:[text stringByAppendingString:@"\n"]
            attributes:@{
                NSForegroundColorAttributeName: TEXT_COLOR,
                NSFontAttributeName: [NSFont fontWithName:@"Menlo" size:12]
            }];

        [[self.outputView textStorage] appendAttributedString:attrStr];
        [self.outputView scrollToEndOfDocument:nil];
    });
}

- (void)clearOutput {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.outputView setString:@""];
    });
}

- (void)focusInput {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.inputField becomeFirstResponder];
    });
}

// Handle Enter key to submit command
- (void)controlTextDidEndEditing:(NSNotification *)notification {
    NSTextField *textField = notification.object;
    if (textField == _inputField) {
        NSString *command = [_inputField.stringValue stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (command.length > 0) {
            // Add to history
            [_commandHistory addObject:command];
            _historyIndex = _commandHistory.count;

            // Echo command to output
            [self appendOutput:[NSString stringWithFormat:@"> %@", command]];

            // Clear input
            _inputField.stringValue = @"";

            // Call callback
            if (s_command_callback) {
                s_command_callback([command UTF8String]);
            }
        }
    }
}

// Handle up/down arrows for history
- (BOOL)control:(NSControl *)control textView:(NSTextView *)textView doCommandBySelector:(SEL)commandSelector {
    if (control == _inputField) {
        if (commandSelector == @selector(moveUp:)) {
            // Previous command
            if (_historyIndex > 0) {
                _historyIndex--;
                _inputField.stringValue = _commandHistory[_historyIndex];
            }
            return YES;
        } else if (commandSelector == @selector(moveDown:)) {
            // Next command
            if (_historyIndex < (NSInteger)_commandHistory.count - 1) {
                _historyIndex++;
                _inputField.stringValue = _commandHistory[_historyIndex];
            } else {
                _historyIndex = _commandHistory.count;
                _inputField.stringValue = @"";
            }
            return YES;
        }
    }
    return NO;
}

@end

// ============================================================================
// Overlay Window - Floating above game
// ============================================================================

@interface BG3SEOverlayWindow : NSWindow
@end

@implementation BG3SEOverlayWindow

- (instancetype)init {
    // Get main screen size
    NSRect screenRect = [[NSScreen mainScreen] frame];

    // Position at top-center of screen
    CGFloat x = (screenRect.size.width - OVERLAY_WIDTH) / 2;
    CGFloat y = screenRect.size.height - OVERLAY_HEIGHT - 50;

    NSRect windowRect = NSMakeRect(x, y, OVERLAY_WIDTH, OVERLAY_HEIGHT);

    self = [super initWithContentRect:windowRect
                            styleMask:NSWindowStyleMaskBorderless
                              backing:NSBackingStoreBuffered
                                defer:NO];

    if (self) {
        // Configure window
        self.level = NSScreenSaverWindowLevel;  // Very high level, above fullscreen
        self.backgroundColor = [NSColor clearColor];
        self.opaque = NO;
        self.hasShadow = YES;
        self.movableByWindowBackground = YES;
        self.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces |
                                   NSWindowCollectionBehaviorFullScreenAuxiliary;

        // Create console view
        s_console_view = [[BG3SEConsoleView alloc] initWithFrame:NSMakeRect(0, 0, OVERLAY_WIDTH, OVERLAY_HEIGHT)];
        self.contentView = s_console_view;
    }

    return self;
}

// Allow key events even when not focused
- (BOOL)canBecomeKeyWindow {
    return YES;
}

- (BOOL)canBecomeMainWindow {
    return NO;
}

@end

// ============================================================================
// Public API Implementation
// ============================================================================

void overlay_init(void) {
    if (s_initialized) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            s_overlay_window = [[BG3SEOverlayWindow alloc] init];

            // Start hidden
            [s_overlay_window orderOut:nil];

            log_message("[Overlay] Console overlay initialized");
            s_initialized = true;
        }
    });
}

void overlay_shutdown(void) {
    if (!s_initialized) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            [s_overlay_window close];
            s_overlay_window = nil;
            s_console_view = nil;
            s_initialized = false;

            log_message("[Overlay] Console overlay shutdown");
        }
    });
}

void overlay_toggle(void) {
    if (!s_initialized || !s_overlay_window) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            if ([s_overlay_window isVisible]) {
                [s_overlay_window orderOut:nil];
                log_message("[Overlay] Hidden");
            } else {
                [s_overlay_window makeKeyAndOrderFront:nil];
                [s_console_view focusInput];
                log_message("[Overlay] Shown");
            }
        }
    });
}

void overlay_show(void) {
    if (!s_initialized || !s_overlay_window) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            [s_overlay_window makeKeyAndOrderFront:nil];
            [s_console_view focusInput];
        }
    });
}

void overlay_hide(void) {
    if (!s_initialized || !s_overlay_window) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            [s_overlay_window orderOut:nil];
        }
    });
}

bool overlay_is_visible(void) {
    if (!s_initialized || !s_overlay_window) return false;

    __block bool visible = false;
    dispatch_sync(dispatch_get_main_queue(), ^{
        visible = [s_overlay_window isVisible];
    });
    return visible;
}

void overlay_append_output(const char *text) {
    if (!s_initialized || !s_console_view || !text) return;

    NSString *nsText = [NSString stringWithUTF8String:text];
    [s_console_view appendOutput:nsText];
}

void overlay_clear_output(void) {
    if (!s_initialized || !s_console_view) return;

    [s_console_view clearOutput];
}

void overlay_set_command_callback(overlay_command_callback callback) {
    s_command_callback = callback;
}

void overlay_focus_input(void) {
    if (!s_initialized || !s_console_view) return;

    [s_console_view focusInput];
}
