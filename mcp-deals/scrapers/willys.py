"""Scraper for Willys.se deals/erbjudanden."""

import logging
from datetime import datetime
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Willys.se uses a React-based frontend. The offers page may load deal data
# via XHR/JSON API. httpx+BS4 is attempted first; if the HTML is an empty
# app shell, playwright would be needed as fallback.


async def scrape(url: str) -> list[dict[str, Any]]:
    """Scrape deals from Willys.

    Tries httpx+BS4 first. Falls back gracefully if JS rendering is required.
    Also attempts to hit a known JSON API endpoint for offers.
    """
    deals: list[dict[str, Any]] = []

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "sv-SE,sv;q=0.9,en;q=0.8",
    }

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=30.0,
            headers=headers,
        ) as client:
            # Strategy 1: Try JSON API that Willys often exposes
            deals = await _try_json_api(client)
            if deals:
                return deals

            # Strategy 2: Parse HTML page
            resp = await client.get(url)
            resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        cards = soup.select(
            ".offer-card, .product-card, [data-testid='product-card'], "
            "[class*='ProductCard'], [class*='OfferCard'], "
            ".js-offer-card, .campaign-product"
        )

        if not cards:
            cards = soup.select(
                "article, .product-list .product, "
                ".offers-container > div, .grid-item"
            )

        for card in cards:
            deal = _parse_card(card)
            if deal and deal.get("product_name"):
                deals.append(deal)

        if not deals:
            logger.info(
                "Willys: No deals found with BS4 – page likely requires "
                "JavaScript rendering (playwright fallback needed)"
            )

    except httpx.HTTPError as e:
        logger.error("Willys: HTTP error: %s", e)
    except Exception as e:
        logger.error("Willys: Unexpected error: %s", e)

    return deals


async def _try_json_api(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Attempt to fetch deals from Willys' internal JSON API."""
    deals: list[dict[str, Any]] = []
    api_url = "https://www.willys.se/search/campaigns/offline"

    try:
        resp = await client.get(
            api_url,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        results = data.get("results", data.get("products", []))
        if isinstance(data, list):
            results = data

        for item in results:
            name = item.get("name") or item.get("productName") or item.get("title")
            if not name:
                continue
            deals.append({
                "store_name": "Willys",
                "product_name": name,
                "description": item.get("description"),
                "deal_price": _safe_float(item.get("priceValue") or item.get("price") or item.get("campaignPrice")),
                "original_price": _safe_float(item.get("comparePrice") or item.get("originalPrice")),
                "discount_pct": _safe_float(item.get("savingsPercent") or item.get("discount")),
                "category": item.get("category") or item.get("categoryName"),
                "image_url": item.get("image", {}).get("url") if isinstance(item.get("image"), dict) else item.get("imageUrl"),
            })

    except Exception as e:
        logger.debug("Willys: JSON API attempt failed: %s", e)

    return deals


def _parse_card(card: BeautifulSoup) -> dict[str, Any]:
    """Extract deal info from a single product card element."""
    deal: dict[str, Any] = {"store_name": "Willys"}

    name_el = card.select_one(
        ".product-name, .offer-name, h2, h3, "
        "[class*='name'], [class*='title'], [class*='Name']"
    )
    deal["product_name"] = name_el.get_text(strip=True) if name_el else None

    desc_el = card.select_one(
        ".product-description, .subtitle, [class*='description']"
    )
    deal["description"] = desc_el.get_text(strip=True) if desc_el else None

    price_el = card.select_one(
        ".price--campaign, .campaign-price, .deal-price, "
        "[class*='campaignPrice'], [class*='dealPrice'], "
        ".price-new"
    )
    deal["deal_price"] = _parse_price(price_el.get_text(strip=True)) if price_el else None

    orig_el = card.select_one(
        ".price--ordinary, .original-price, .price-old, "
        "[class*='originalPrice'], del, s"
    )
    deal["original_price"] = _parse_price(orig_el.get_text(strip=True)) if orig_el else None

    disc_el = card.select_one(
        ".discount, .savings, .badge, [class*='discount'], [class*='savings']"
    )
    if disc_el:
        deal["discount_pct"] = _parse_discount(disc_el.get_text(strip=True))

    cat_el = card.select_one("[class*='category'], .tag")
    deal["category"] = cat_el.get_text(strip=True) if cat_el else None

    date_el = card.select_one("[class*='valid'], [class*='date'], time")
    if date_el:
        deal["valid_to"] = _parse_date(date_el.get("datetime") or date_el.get_text(strip=True))

    img_el = card.select_one("img")
    if img_el:
        deal["image_url"] = img_el.get("src") or img_el.get("data-src")

    return deal


def _safe_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def _parse_price(text: str) -> float | None:
    if not text:
        return None
    import re
    text = text.replace(",", ".").replace(":", ".")
    match = re.search(r"(\d+\.?\d*)", text)
    return float(match.group(1)) if match else None


def _parse_discount(text: str) -> float | None:
    if not text:
        return None
    import re
    match = re.search(r"(\d+)\s*%", text)
    return float(match.group(1)) if match else None


def _parse_date(text: str) -> datetime | None:
    if not text:
        return None
    from dateutil import parser as dateparser
    try:
        return dateparser.parse(text, dayfirst=True)
    except Exception:
        return None
