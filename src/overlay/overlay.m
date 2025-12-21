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
#define TEXT_COLOR [NSColor colorWithRed:1.0 green:1.0 blue:1.0 alpha:1.0]  // Pure white for legibility
#define DIM_TEXT_COLOR [NSColor colorWithRed:0.7 green:0.7 blue:0.7 alpha:1.0]  // Dimmer for brackets
#define INPUT_BG_COLOR [NSColor colorWithRed:0.12 green:0.12 blue:0.14 alpha:1.0]
#define CLOSE_BUTTON_COLOR [NSColor colorWithRed:0.6 green:0.6 blue:0.6 alpha:1.0]
#define CLOSE_BUTTON_HOVER [NSColor colorWithRed:0.9 green:0.3 blue:0.3 alpha:1.0]

// Dimensions
#define OVERLAY_WIDTH 800
#define OVERLAY_HEIGHT 480
#define TANIT_SIZE 36
#define BORDER_WIDTH 2
#define PADDING 16
#define FONT_SIZE 13
#define INPUT_HEIGHT 32
#define TAB_HEIGHT 28
#define TAB_WIDTH 80

// Tab indices
typedef enum {
    TAB_CONSOLE = 0,
    TAB_MODS = 1,
    TAB_ENTITIES = 2,
    TAB_COUNT = 3
} ConsoleTab;

// ============================================================================
// Tanit Symbol View - Loads PNG from assets
// ============================================================================

@interface BG3SETanitView : NSImageView
@end

@implementation BG3SETanitView

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.wantsLayer = YES;
        self.imageScaling = NSImageScaleProportionallyUpOrDown;
        self.imageAlignment = NSImageAlignCenter;

        // Load the Tanit PNG from the dylib bundle or executable path
        [self loadTanitImage];

        // Add subtle pulsing glow animation
        [self addGlowAnimation];
    }
    return self;
}

- (void)loadTanitImage {
    // Try multiple paths to find the Tanit PNG
    NSArray *searchPaths = @[
        // Relative to executable
        [[[NSBundle mainBundle] executablePath] stringByDeletingLastPathComponent],
        // Development path
        @"/Users/tomdimino/Desktop/Programming/bg3se-macos/assets",
        // Alongside the dylib
        @".",
    ];

    for (NSString *basePath in searchPaths) {
        NSString *imagePath = [basePath stringByAppendingPathComponent:@"tanit.png"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:imagePath]) {
            NSImage *image = [[NSImage alloc] initWithContentsOfFile:imagePath];
            if (image) {
                self.image = image;
                return;
            }
        }
    }

    // Fallback: create a simple gold circle if PNG not found
    NSImage *fallback = [[NSImage alloc] initWithSize:NSMakeSize(64, 64)];
    [fallback lockFocus];
    [[NSColor colorWithRed:0.992 green:0.878 blue:0.278 alpha:1.0] setFill];
    [[NSBezierPath bezierPathWithOvalInRect:NSMakeRect(8, 8, 48, 48)] fill];
    [fallback unlockFocus];
    self.image = fallback;
}

- (void)addGlowAnimation {
    // Pulsing opacity animation for subtle glow effect
    CABasicAnimation *pulseAnim = [CABasicAnimation animationWithKeyPath:@"opacity"];
    pulseAnim.fromValue = @0.85;
    pulseAnim.toValue = @1.0;
    pulseAnim.duration = 2.0;
    pulseAnim.autoreverses = YES;
    pulseAnim.repeatCount = HUGE_VALF;
    pulseAnim.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
    [self.layer addAnimation:pulseAnim forKey:@"pulse"];
}

- (BOOL)isFlipped {
    return YES;
}

@end

// ============================================================================
// Close Button - X button to close the console
// ============================================================================

@interface BG3SECloseButton : NSButton
@property (nonatomic, assign) BOOL isHovered;
@end

@implementation BG3SECloseButton

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        // Use NSButtonTypeMomentaryChange for custom drawn buttons
        [self setButtonType:NSButtonTypeMomentaryChange];
        self.bordered = NO;
        self.wantsLayer = YES;
        self.layer.cornerRadius = frame.size.width / 2;
        self.title = @"";
        self.imagePosition = NSNoImage;
        _isHovered = NO;

        // Track mouse for hover effect
        NSTrackingArea *trackingArea = [[NSTrackingArea alloc]
            initWithRect:self.bounds
            options:(NSTrackingMouseEnteredAndExited | NSTrackingActiveAlways)
            owner:self
            userInfo:nil];
        [self addTrackingArea:trackingArea];
    }
    return self;
}

- (void)drawRect:(NSRect)dirtyRect {
    CGFloat w = self.bounds.size.width;
    CGFloat h = self.bounds.size.height;

    // Background circle on hover
    if (_isHovered) {
        [[NSColor colorWithRed:0.3 green:0.3 blue:0.3 alpha:0.8] setFill];
        [[NSBezierPath bezierPathWithOvalInRect:self.bounds] fill];
    }

    // Draw X
    NSColor *xColor = _isHovered ? CLOSE_BUTTON_HOVER : CLOSE_BUTTON_COLOR;
    [xColor setStroke];

    NSBezierPath *path = [NSBezierPath bezierPath];
    path.lineWidth = 2.0;
    path.lineCapStyle = NSLineCapStyleRound;

    CGFloat inset = 6;
    [path moveToPoint:NSMakePoint(inset, inset)];
    [path lineToPoint:NSMakePoint(w - inset, h - inset)];
    [path moveToPoint:NSMakePoint(w - inset, inset)];
    [path lineToPoint:NSMakePoint(inset, h - inset)];
    [path stroke];
}

- (void)mouseEntered:(NSEvent *)event {
    _isHovered = YES;
    [self setNeedsDisplay:YES];
}

- (void)mouseExited:(NSEvent *)event {
    _isHovered = NO;
    [self setNeedsDisplay:YES];
}

@end

// ============================================================================
// Tab Button - Individual tab in the tab bar
// ============================================================================

@interface BG3SETabButton : NSButton
@property (nonatomic, assign) BOOL isSelected;
@property (nonatomic, assign) ConsoleTab tabIndex;
@end

@implementation BG3SETabButton

- (instancetype)initWithFrame:(NSRect)frame title:(NSString *)title tabIndex:(ConsoleTab)idx {
    self = [super initWithFrame:frame];
    if (self) {
        // Use NSButtonTypeMomentaryChange for custom drawn buttons
        [self setButtonType:NSButtonTypeMomentaryChange];
        self.title = title;
        self.bordered = NO;
        self.wantsLayer = YES;
        self.imagePosition = NSNoImage;
        _tabIndex = idx;
        _isSelected = NO;
        self.font = [NSFont systemFontOfSize:11 weight:NSFontWeightMedium];
    }
    return self;
}

- (void)drawRect:(NSRect)dirtyRect {
    if (_isSelected) {
        // Selected tab - gold underline
        [[NSColor colorWithRed:0.15 green:0.15 blue:0.17 alpha:1.0] setFill];
        NSRectFill(self.bounds);

        // Gold underline
        [TANIT_PRIMARY setFill];
        NSRectFill(NSMakeRect(0, self.bounds.size.height - 2, self.bounds.size.width, 2));
    }

    // Draw title
    NSColor *textColor = _isSelected ? TANIT_PRIMARY : [NSColor colorWithRed:0.6 green:0.6 blue:0.6 alpha:1.0];
    NSDictionary *attrs = @{
        NSFontAttributeName: self.font,
        NSForegroundColorAttributeName: textColor
    };
    NSSize textSize = [self.title sizeWithAttributes:attrs];
    CGFloat x = (self.bounds.size.width - textSize.width) / 2;
    CGFloat y = (self.bounds.size.height - textSize.height) / 2;
    [self.title drawAtPoint:NSMakePoint(x, y) withAttributes:attrs];
}

- (void)setIsSelected:(BOOL)isSelected {
    _isSelected = isSelected;
    [self setNeedsDisplay:YES];
}

@end

// ============================================================================
// Log Level Colors - For syntax highlighting in output
// ============================================================================

static NSColor* colorForLogLevel(const char* text) {
    if (!text) return TEXT_COLOR;

    // Error patterns
    if (strstr(text, "[ERROR]") || strstr(text, "Error:") || strstr(text, "error:") ||
        strstr(text, "FAILED") || strstr(text, "Exception")) {
        return [NSColor colorWithRed:1.0 green:0.4 blue:0.4 alpha:1.0];  // Red
    }
    // Warning patterns
    if (strstr(text, "[WARN]") || strstr(text, "Warning:") || strstr(text, "warning:")) {
        return [NSColor colorWithRed:1.0 green:0.8 blue:0.3 alpha:1.0];  // Yellow/amber
    }
    // Success patterns
    if (strstr(text, "[OK]") || strstr(text, "Success") || strstr(text, "Loaded") ||
        strstr(text, "initialized") || strstr(text, "enabled")) {
        return [NSColor colorWithRed:0.4 green:0.9 blue:0.5 alpha:1.0];  // Green
    }
    // Debug/trace patterns
    if (strstr(text, "[DEBUG]") || strstr(text, "[TRACE]") || strstr(text, "-->")) {
        return [NSColor colorWithRed:0.5 green:0.7 blue:0.9 alpha:1.0];  // Light blue
    }
    // Entity/test tags
    if (strstr(text, "[EntityTest]") || strstr(text, "[StaticData]")) {
        return [NSColor colorWithRed:0.7 green:0.6 blue:0.9 alpha:1.0];  // Purple
    }

    return TEXT_COLOR;
}

// ============================================================================
// Console View - Input field + Output text area with tabs
// ============================================================================

@interface BG3SEConsoleView : NSView <NSTextFieldDelegate>
@property (nonatomic, strong) NSScrollView *scrollView;
@property (nonatomic, strong) NSTextView *outputView;
@property (nonatomic, strong) NSTextField *inputField;
@property (nonatomic, strong) NSTextField *promptLabel;
@property (nonatomic, strong) BG3SETanitView *tanitView;
@property (nonatomic, strong) BG3SECloseButton *closeButton;
@property (nonatomic, strong) NSMutableArray<NSString *> *commandHistory;
@property (nonatomic, assign) NSInteger historyIndex;
// Tab system
@property (nonatomic, strong) NSView *tabBar;
@property (nonatomic, strong) NSMutableArray<BG3SETabButton *> *tabButtons;
@property (nonatomic, assign) ConsoleTab currentTab;
// Mods view
@property (nonatomic, strong) NSScrollView *modsScrollView;
@property (nonatomic, strong) NSView *modsContentView;
// Entities view (placeholder)
@property (nonatomic, strong) NSView *entitiesView;
// Input area container (for hiding on non-console tabs)
@property (nonatomic, strong) NSView *inputArea;
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

    // ========== Header Area ==========

    // Tanit symbol in top-left corner
    _tanitView = [[BG3SETanitView alloc] initWithFrame:NSMakeRect(PADDING, PADDING, TANIT_SIZE, TANIT_SIZE)];
    [self addSubview:_tanitView];

    // Title label next to Tanit - vertically centered with symbol
    CGFloat titleY = PADDING + (TANIT_SIZE - 18) / 2;
    NSTextField *titleLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING + TANIT_SIZE + 10, titleY, 200, 18)];
    titleLabel.stringValue = @"BG3SE Console";
    titleLabel.font = [NSFont boldSystemFontOfSize:15];
    titleLabel.textColor = TANIT_PRIMARY;
    titleLabel.backgroundColor = [NSColor clearColor];
    titleLabel.bordered = NO;
    titleLabel.editable = NO;
    titleLabel.selectable = NO;
    [self addSubview:titleLabel];

    // Close button (X) in top-right corner
    CGFloat closeButtonSize = 24;
    _closeButton = [[BG3SECloseButton alloc] initWithFrame:NSMakeRect(w - PADDING - closeButtonSize, PADDING + (TANIT_SIZE - closeButtonSize) / 2, closeButtonSize, closeButtonSize)];
    _closeButton.target = self;
    _closeButton.action = @selector(closeButtonClicked:);
    [self addSubview:_closeButton];

    // ========== Tab Bar ==========

    CGFloat tabBarY = PADDING + TANIT_SIZE + 8;
    _tabBar = [[NSView alloc] initWithFrame:NSMakeRect(PADDING, tabBarY, w - PADDING * 2, TAB_HEIGHT)];
    _tabBar.wantsLayer = YES;
    _tabBar.layer.backgroundColor = [NSColor colorWithRed:0.1 green:0.1 blue:0.12 alpha:1.0].CGColor;

    _tabButtons = [NSMutableArray array];
    NSArray *tabTitles = @[@"Console", @"Mods", @"Entities"];
    for (int i = 0; i < TAB_COUNT; i++) {
        BG3SETabButton *tab = [[BG3SETabButton alloc] initWithFrame:NSMakeRect(i * TAB_WIDTH, 0, TAB_WIDTH, TAB_HEIGHT)
                                                               title:tabTitles[i]
                                                            tabIndex:i];
        tab.target = self;
        tab.action = @selector(tabClicked:);
        [_tabBar addSubview:tab];
        [_tabButtons addObject:tab];
    }
    _currentTab = TAB_CONSOLE;
    _tabButtons[TAB_CONSOLE].isSelected = YES;
    [self addSubview:_tabBar];

    // ========== Content Area (below tabs) ==========

    CGFloat contentTop = tabBarY + TAB_HEIGHT + 8;
    CGFloat inputAreaHeight = INPUT_HEIGHT + PADDING;
    CGFloat contentHeight = h - contentTop - inputAreaHeight;

    // --- Console Tab: Output view ---
    _scrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(PADDING, contentTop, w - PADDING * 2, contentHeight)];
    _scrollView.hasVerticalScroller = YES;
    _scrollView.hasHorizontalScroller = NO;
    _scrollView.autohidesScrollers = YES;
    _scrollView.borderType = NSNoBorder;
    _scrollView.backgroundColor = [NSColor clearColor];
    _scrollView.drawsBackground = NO;

    _outputView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, w - PADDING * 2 - 15, contentHeight)];
    _outputView.backgroundColor = [NSColor clearColor];
    _outputView.drawsBackground = NO;
    _outputView.textColor = TEXT_COLOR;
    _outputView.font = [NSFont fontWithName:@"Menlo" size:FONT_SIZE];
    _outputView.editable = NO;
    _outputView.selectable = YES;
    _outputView.textContainerInset = NSMakeSize(4, 4);
    [_outputView setAllowsUndo:NO];
    [_outputView setRichText:YES];  // Enable rich text for colored output
    [_outputView setImportsGraphics:NO];
    [_outputView setAutoresizingMask:NSViewWidthSizable];

    _scrollView.documentView = _outputView;
    [self addSubview:_scrollView];

    // --- Mods Tab: Mods list view (initially hidden) ---
    _modsScrollView = [[NSScrollView alloc] initWithFrame:NSMakeRect(PADDING, contentTop, w - PADDING * 2, contentHeight)];
    _modsScrollView.hasVerticalScroller = YES;
    _modsScrollView.hasHorizontalScroller = NO;
    _modsScrollView.autohidesScrollers = YES;
    _modsScrollView.borderType = NSNoBorder;
    _modsScrollView.backgroundColor = [NSColor clearColor];
    _modsScrollView.drawsBackground = NO;
    _modsScrollView.hidden = YES;

    _modsContentView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, w - PADDING * 2 - 15, contentHeight)];
    _modsContentView.wantsLayer = YES;
    _modsScrollView.documentView = _modsContentView;
    [self addSubview:_modsScrollView];

    // --- Entities Tab: Placeholder (initially hidden) ---
    _entitiesView = [[NSView alloc] initWithFrame:NSMakeRect(PADDING, contentTop, w - PADDING * 2, contentHeight)];
    _entitiesView.wantsLayer = YES;
    _entitiesView.hidden = YES;

    // Placeholder label for entities
    NSTextField *entitiesLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(20, contentHeight / 2, 300, 40)];
    entitiesLabel.stringValue = @"Entity Browser\n(Coming Soon)";
    entitiesLabel.font = [NSFont systemFontOfSize:16 weight:NSFontWeightLight];
    entitiesLabel.textColor = [NSColor colorWithRed:0.5 green:0.5 blue:0.5 alpha:1.0];
    entitiesLabel.backgroundColor = [NSColor clearColor];
    entitiesLabel.bordered = NO;
    entitiesLabel.editable = NO;
    entitiesLabel.alignment = NSTextAlignmentCenter;
    [_entitiesView addSubview:entitiesLabel];
    [self addSubview:_entitiesView];

    // ========== Input Area (for Console tab) ==========

    CGFloat inputY = h - PADDING - INPUT_HEIGHT;
    _inputArea = [[NSView alloc] initWithFrame:NSMakeRect(0, inputY - 4, w, INPUT_HEIGHT + 8)];

    CGFloat promptWidth = 20;

    // Prompt label ">"
    _promptLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING, 4, promptWidth, INPUT_HEIGHT)];
    _promptLabel.stringValue = @">";
    _promptLabel.font = [NSFont fontWithName:@"Menlo-Bold" size:FONT_SIZE];
    _promptLabel.textColor = TANIT_PRIMARY;
    _promptLabel.backgroundColor = [NSColor clearColor];
    _promptLabel.bordered = NO;
    _promptLabel.editable = NO;
    _promptLabel.selectable = NO;
    NSTextFieldCell *promptCell = _promptLabel.cell;
    [promptCell setLineBreakMode:NSLineBreakByClipping];
    [_inputArea addSubview:_promptLabel];

    // Input field
    _inputField = [[NSTextField alloc] initWithFrame:NSMakeRect(PADDING + promptWidth, 4, w - PADDING * 2 - promptWidth, INPUT_HEIGHT)];
    _inputField.font = [NSFont fontWithName:@"Menlo" size:FONT_SIZE];
    _inputField.textColor = TEXT_COLOR;
    _inputField.backgroundColor = INPUT_BG_COLOR;
    _inputField.bordered = NO;
    _inputField.focusRingType = NSFocusRingTypeNone;
    _inputField.placeholderString = @"Enter Lua command...";
    _inputField.delegate = self;
    _inputField.wantsLayer = YES;
    _inputField.layer.cornerRadius = 4;
    _inputField.allowsEditingTextAttributes = NO;
    [[_inputField cell] setUsesSingleLineMode:YES];
    [[_inputField cell] setScrollable:YES];
    [_inputArea addSubview:_inputField];

    [self addSubview:_inputArea];

    // Initialize mods list with placeholder data
    [self updateModsList];
}

// Tab switching - with safety checks to prevent crashes
- (void)tabClicked:(id)sender {
    @try {
        // Safety: verify sender is valid
        if (!sender || ![sender isKindOfClass:[BG3SETabButton class]]) {
            NSLog(@"[BG3SE Console] tabClicked: invalid sender");
            return;
        }

        BG3SETabButton *tabButton = (BG3SETabButton *)sender;
        ConsoleTab newTab = tabButton.tabIndex;

        // Safety: bounds check
        if (newTab < 0 || newTab >= TAB_COUNT) {
            NSLog(@"[BG3SE Console] tabClicked: invalid tab index %d", (int)newTab);
            return;
        }

        if (_currentTab == newTab) return;

        // Safety: verify array exists and indices are valid
        if (!_tabButtons || _tabButtons.count == 0) {
            NSLog(@"[BG3SE Console] tabClicked: tabButtons not initialized");
            return;
        }

        if (_currentTab >= (ConsoleTab)_tabButtons.count || newTab >= (ConsoleTab)_tabButtons.count) {
            NSLog(@"[BG3SE Console] tabClicked: index out of bounds");
            return;
        }

        // Deselect old tab
        _tabButtons[_currentTab].isSelected = NO;

        // Select new tab
        _currentTab = newTab;
        tabButton.isSelected = YES;

        // Defer view changes to next run loop iteration to avoid issues during event handling
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                // Show/hide views based on tab - with nil checks
                if (self->_scrollView) self->_scrollView.hidden = (self->_currentTab != TAB_CONSOLE);
                if (self->_modsScrollView) self->_modsScrollView.hidden = (self->_currentTab != TAB_MODS);
                if (self->_entitiesView) self->_entitiesView.hidden = (self->_currentTab != TAB_ENTITIES);
                if (self->_inputArea) self->_inputArea.hidden = (self->_currentTab != TAB_CONSOLE);

                if (self->_currentTab == TAB_MODS && self->_modsContentView) {
                    [self updateModsList];
                }
            } @catch (NSException *e) {
                NSLog(@"[BG3SE Console] Exception updating views: %@", e);
            }
        });

    } @catch (NSException *exception) {
        NSLog(@"[BG3SE Console] Exception in tabClicked: %@ - %@", exception.name, exception.reason);
    }
}

// Update mods list display - with safety checks
- (void)updateModsList {
    @try {
        // Safety: verify view exists
        if (!_modsContentView) {
            NSLog(@"[BG3SE Console] updateModsList: modsContentView is nil");
            return;
        }

        // Clear existing content
        for (NSView *subview in [_modsContentView.subviews copy]) {
            [subview removeFromSuperview];
        }

        // Placeholder mod data - in real implementation, this comes from the mod loader
        NSArray *mods = @[
            @{@"name": @"EntityTest", @"version": @"1.0", @"status": @"loaded", @"author": @"BG3SE"},
            @{@"name": @"StaticDataTest", @"version": @"1.0", @"status": @"loaded", @"author": @"BG3SE"},
            @{@"name": @"ExampleMod", @"version": @"0.5", @"status": @"error", @"author": @"Community"},
        ];

        CGFloat rowHeight = 50;
        CGFloat contentHeight = _modsContentView.bounds.size.height;
        CGFloat contentWidth = _modsContentView.bounds.size.width;
        if (contentHeight <= 0) contentHeight = 300; // Fallback
        if (contentWidth <= 0) contentWidth = 700; // Fallback
        CGFloat y = contentHeight - rowHeight;

        for (NSDictionary *mod in mods) {
            NSView *row = [[NSView alloc] initWithFrame:NSMakeRect(0, y, contentWidth, rowHeight)];
            row.wantsLayer = YES;
            row.layer.backgroundColor = [NSColor colorWithRed:0.12 green:0.12 blue:0.14 alpha:1.0].CGColor;
            row.layer.cornerRadius = 4;

            // Mod name
            NSTextField *nameLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(12, 26, 200, 18)];
            nameLabel.stringValue = mod[@"name"];
            nameLabel.font = [NSFont systemFontOfSize:14 weight:NSFontWeightMedium];
            nameLabel.textColor = TEXT_COLOR;
            nameLabel.backgroundColor = [NSColor clearColor];
            nameLabel.bordered = NO;
            nameLabel.editable = NO;
            [row addSubview:nameLabel];

            // Version and author
            NSTextField *infoLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(12, 8, 200, 14)];
            infoLabel.stringValue = [NSString stringWithFormat:@"v%@ by %@", mod[@"version"], mod[@"author"]];
            infoLabel.font = [NSFont systemFontOfSize:11];
            infoLabel.textColor = [NSColor colorWithRed:0.5 green:0.5 blue:0.5 alpha:1.0];
            infoLabel.backgroundColor = [NSColor clearColor];
            infoLabel.bordered = NO;
            infoLabel.editable = NO;
            [row addSubview:infoLabel];

            // Status badge
            NSString *status = mod[@"status"];
            NSColor *statusColor = [status isEqualToString:@"loaded"] ?
                [NSColor colorWithRed:0.4 green:0.9 blue:0.5 alpha:1.0] :
                [NSColor colorWithRed:1.0 green:0.4 blue:0.4 alpha:1.0];

            NSTextField *statusLabel = [[NSTextField alloc] initWithFrame:NSMakeRect(contentWidth - 80, 16, 60, 18)];
            statusLabel.stringValue = [status uppercaseString];
            statusLabel.font = [NSFont systemFontOfSize:10 weight:NSFontWeightBold];
            statusLabel.textColor = statusColor;
            statusLabel.backgroundColor = [NSColor clearColor];
            statusLabel.bordered = NO;
            statusLabel.editable = NO;
            statusLabel.alignment = NSTextAlignmentRight;
            [row addSubview:statusLabel];

            [_modsContentView addSubview:row];
            y -= (rowHeight + 6);
        }

        // Resize content view to fit all mods
        CGFloat totalHeight = mods.count * (rowHeight + 6);
        if (totalHeight > _modsContentView.bounds.size.height) {
            NSRect frame = _modsContentView.frame;
            frame.size.height = totalHeight;
            _modsContentView.frame = frame;
        }
    } @catch (NSException *exception) {
        NSLog(@"[BG3SE Console] Exception in updateModsList: %@ - %@", exception.name, exception.reason);
    }
}

- (void)closeButtonClicked:(id)sender {
    overlay_hide();
}

- (BOOL)isFlipped {
    return YES;
}

- (void)appendOutput:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Determine color based on log level patterns
        NSColor *textColor = colorForLogLevel([text UTF8String]);

        NSAttributedString *attrStr = [[NSAttributedString alloc]
            initWithString:[text stringByAppendingString:@"\n"]
            attributes:@{
                NSForegroundColorAttributeName: textColor,
                NSFontAttributeName: [NSFont fontWithName:@"Menlo" size:FONT_SIZE]
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
        // Only submit when the user pressed Enter. Focus loss (e.g. clicking tabs)
        // can also end editing and must NOT execute commands.
        NSNumber *movement = notification.userInfo[@"NSTextMovement"];
        if (!movement || movement.integerValue != NSReturnTextMovement) {
            return;
        }

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

// Handle up/down arrows for history, Escape to close, and block newlines
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
        } else if (commandSelector == @selector(cancelOperation:)) {
            // Escape key - hide overlay
            overlay_hide();
            return YES;
        } else if (commandSelector == @selector(insertNewline:) ||
                   commandSelector == @selector(insertNewlineIgnoringFieldEditor:)) {
            // Shift+Enter or other newline attempts - ignore in single-line mode
            // This prevents crashes from attempting to insert newlines
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

            LOG_CONSOLE_INFO("Console overlay initialized");
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

            LOG_CONSOLE_INFO("Console overlay shutdown");
        }
    });
}

void overlay_toggle(void) {
    if (!s_initialized || !s_overlay_window) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        @autoreleasepool {
            if ([s_overlay_window isVisible]) {
                [s_overlay_window orderOut:nil];
                LOG_CONSOLE_INFO("Hidden");
            } else {
                [s_overlay_window makeKeyAndOrderFront:nil];
                [s_console_view focusInput];
                LOG_CONSOLE_INFO("Shown");
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
