"""Scraper for Hemkop.se deals/erbjudanden."""

import logging
from datetime import datetime
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Hemkop typically renders deals via JS frameworks. httpx+BS4 may return
# an empty shell. If no deals are found, playwright would be needed as fallback.
# NOTE: Real CSS selectors will need adjustment once the actual page structure
# is inspected in a browser.


async def scrape(url: str) -> list[dict[str, Any]]:
    """Scrape deals from Hemkop.

    Tries httpx+BS4 first. Returns empty list gracefully if the page
    requires JavaScript rendering (playwright fallback needed).
    """
    deals: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=30.0,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "sv-SE,sv;q=0.9,en;q=0.8",
            },
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # Strategy 1: Look for product/offer cards in common patterns
        cards = soup.select(
            ".product-card, .offer-card, .deal-card, "
            "[data-testid='offer-card'], [class*='ProductCard'], "
            "[class*='OfferCard'], .kampanj-item"
        )

        if not cards:
            # Strategy 2: Try broader patterns typical of Swedish grocery sites
            cards = soup.select(
                "article.product, .product-list .product, "
                ".offers-grid > div, .campaign-products .item"
            )

        for card in cards:
            deal = _parse_card(card)
            if deal and deal.get("product_name"):
                deals.append(deal)

        if not deals:
            logger.info(
                "Hemkop: No deals found with BS4 – page likely requires "
                "JavaScript rendering (playwright fallback needed)"
            )

    except httpx.HTTPError as e:
        logger.error("Hemkop: HTTP error fetching %s: %s", url, e)
    except Exception as e:
        logger.error("Hemkop: Unexpected error: %s", e)

    return deals


def _parse_card(card: BeautifulSoup) -> dict[str, Any]:
    """Extract deal info from a single product card element."""
    deal: dict[str, Any] = {"store_name": "Hemkop"}

    # Product name
    name_el = card.select_one(
        ".product-name, .product-title, h2, h3, "
        "[class*='name'], [class*='title']"
    )
    deal["product_name"] = name_el.get_text(strip=True) if name_el else None

    # Description
    desc_el = card.select_one(
        ".product-description, .subtitle, .details, "
        "[class*='description'], [class*='subtitle']"
    )
    deal["description"] = desc_el.get_text(strip=True) if desc_el else None

    # Deal price
    price_el = card.select_one(
        ".price--campaign, .deal-price, .campaign-price, "
        "[class*='campaignPrice'], [class*='deal-price'], "
        ".price-new, .price--current"
    )
    deal["deal_price"] = _parse_price(price_el.get_text(strip=True)) if price_el else None

    # Original price
    orig_el = card.select_one(
        ".price--ordinary, .original-price, .price-old, "
        "[class*='originalPrice'], [class*='ordinaryPrice'], "
        ".price--was, del, s"
    )
    deal["original_price"] = _parse_price(orig_el.get_text(strip=True)) if orig_el else None

    # Discount percentage
    disc_el = card.select_one(
        ".discount, .badge, .savings, [class*='discount'], "
        "[class*='savings'], [class*='badge']"
    )
    if disc_el:
        deal["discount_pct"] = _parse_discount(disc_el.get_text(strip=True))

    # Category
    cat_el = card.select_one("[class*='category'], .tag, .label")
    deal["category"] = cat_el.get_text(strip=True) if cat_el else None

    # Valid to
    date_el = card.select_one("[class*='valid'], [class*='date'], time")
    if date_el:
        deal["valid_to"] = _parse_date(date_el.get("datetime") or date_el.get_text(strip=True))

    # Image URL
    img_el = card.select_one("img")
    if img_el:
        deal["image_url"] = img_el.get("src") or img_el.get("data-src")

    return deal


def _parse_price(text: str) -> float | None:
    """Extract numeric price from text like '29:90 kr' or '29.90'."""
    if not text:
        return None
    import re
    text = text.replace(",", ".").replace(":", ".")
    match = re.search(r"(\d+\.?\d*)", text)
    return float(match.group(1)) if match else None


def _parse_discount(text: str) -> float | None:
    """Extract discount percentage from text like '-30%' or 'Spara 30%'."""
    if not text:
        return None
    import re
    match = re.search(r"(\d+)\s*%", text)
    return float(match.group(1)) if match else None


def _parse_date(text: str) -> datetime | None:
    """Try to parse a date string."""
    if not text:
        return None
    from dateutil import parser as dateparser
    try:
        return dateparser.parse(text, dayfirst=True)
    except Exception:
        return None
