// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.content_public.browser;

import org.chromium.content.browser.RenderCoordinatesImpl;

/**
 * Provides dimension/coordinate information of the view rendered by content layer.
 */
public interface RenderCoordinates {
    /**
     * @return {@link Coord} instance associated with the given {@link WebContents}.
     */
    static RenderCoordinates fromWebContents(WebContents webContents) {
        return RenderCoordinatesImpl.fromWebContents(webContents);
    }

    /**
     * @return Horizontal scroll offset in physical pixels (approx, integer).
     */
    int getScrollXPixInt();

    /**
     * @return Vertical scroll offset in physical pixels (approx, integer).
     */
    int getScrollYPixInt();

    /**
     * @return Approximate width of the content in physical pixels (integer).
     */
    int getContentWidthPixInt();

    /**
     * @return Approximate height of the content in physical pixels (integer).
     */
    int getContentHeightPixInt();

    /**
     * @return Render-reported width of the viewport in physical pixels (approx, integer).
     */
    int getLastFrameViewportWidthPixInt();

    /**
     * @return Render-reported height of the viewport in physical pixels (approx, integer).
     */
    int getLastFrameViewportHeightPixInt();
}
