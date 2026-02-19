"""Scraper for Lidl.se deals/erbjudanden."""

import logging
from datetime import datetime
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Lidl's website is often more static-friendly than other Swedish grocery
# sites, but the deals section may still require JS. httpx+BS4 is tried first.


async def scrape(url: str) -> list[dict[str, Any]]:
    """Scrape deals from Lidl.

    Tries httpx+BS4 first. Returns empty list if JS rendering is required.
    Also attempts to hit Lidl's known JSON endpoints for offer data.
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
            # Strategy 1: Try Lidl's leaflet/flyer JSON API
            deals = await _try_json_api(client)
            if deals:
                return deals

            # Strategy 2: Parse HTML
            resp = await client.get(url)
            resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # Lidl uses specific class patterns for their offer grid
        cards = soup.select(
            ".product-grid-box, .offer-card, .ret-o-card, "
            "[data-testid='product'], [class*='AProductCard'], "
            ".nuc-a-product-card, .lidl-m-product-grid-item"
        )

        if not cards:
            cards = soup.select(
                ".product, article.offer, .grid-box, "
                ".ods-tile, [class*='product-card']"
            )

        for card in cards:
            deal = _parse_card(card)
            if deal and deal.get("product_name"):
                deals.append(deal)

        if not deals:
            logger.info(
                "Lidl: No deals found with BS4 – page likely requires "
                "JavaScript rendering (playwright fallback needed)"
            )

    except httpx.HTTPError as e:
        logger.error("Lidl: HTTP error: %s", e)
    except Exception as e:
        logger.error("Lidl: Unexpected error: %s", e)

    return deals


async def _try_json_api(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Attempt to fetch deals from Lidl's internal JSON API."""
    deals: list[dict[str, Any]] = []
    # Lidl sometimes exposes offer data via a leaflet API
    api_url = "https://www.lidl.se/q/api/content/v1/se/sv/offers"

    try:
        resp = await client.get(
            api_url,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return []

        data = resp.json()
        items = data.get("items", data.get("offers", data.get("products", [])))
        if isinstance(data, list):
            items = data

        for item in items:
            name = item.get("title") or item.get("name") or item.get("productName")
            if not name:
                continue
            deals.append({
                "store_name": "Lidl",
                "product_name": name,
                "description": item.get("description") or item.get("subtitle"),
                "deal_price": _safe_float(item.get("price", {}).get("value") if isinstance(item.get("price"), dict) else item.get("price")),
                "original_price": _safe_float(item.get("oldPrice", {}).get("value") if isinstance(item.get("oldPrice"), dict) else item.get("oldPrice")),
                "discount_pct": _safe_float(item.get("discount")),
                "category": item.get("category") or item.get("categoryName"),
                "image_url": item.get("image") if isinstance(item.get("image"), str) else (item.get("image", {}) or {}).get("url"),
                "valid_from": _parse_date(item.get("validFrom") or item.get("startDate")),
                "valid_to": _parse_date(item.get("validTo") or item.get("endDate")),
            })

    except Exception as e:
        logger.debug("Lidl: JSON API attempt failed: %s", e)

    return deals


def _parse_card(card: BeautifulSoup) -> dict[str, Any]:
    """Extract deal info from a single product card element."""
    deal: dict[str, Any] = {"store_name": "Lidl"}

    name_el = card.select_one(
        ".product-grid-box__title, .ret-o-card__headline, "
        "h2, h3, [class*='title'], [class*='name'], "
        "[class*='Title'], [class*='Name']"
    )
    deal["product_name"] = name_el.get_text(strip=True) if name_el else None

    desc_el = card.select_one(
        ".product-grid-box__desc, .ret-o-card__sub-headline, "
        "[class*='description'], [class*='subtitle']"
    )
    deal["description"] = desc_el.get_text(strip=True) if desc_el else None

    price_el = card.select_one(
        ".m-price__price, .pricebox__price, .price--action, "
        "[class*='currentPrice'], [class*='actionPrice'], "
        ".price-new, .price--highlight"
    )
    deal["deal_price"] = _parse_price(price_el.get_text(strip=True)) if price_el else None

    orig_el = card.select_one(
        ".m-price__rrp, .pricebox__old-price, .price--old, "
        "[class*='oldPrice'], [class*='strikethrough'], del, s"
    )
    deal["original_price"] = _parse_price(orig_el.get_text(strip=True)) if orig_el else None

    disc_el = card.select_one(
        ".m-price__label, .badge, .discount, "
        "[class*='discount'], [class*='savings'], [class*='badge']"
    )
    if disc_el:
        deal["discount_pct"] = _parse_discount(disc_el.get_text(strip=True))

    cat_el = card.select_one("[class*='category'], .tag, .label")
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
