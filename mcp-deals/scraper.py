"""ScraperRunner: orchestrates deal scraping and SQLite caching."""

import asyncio
import importlib
import logging
import os
import unicodedata
from datetime import datetime, timedelta
from typing import Any

from sqlmodel import Session, select

logger = logging.getLogger(__name__)

# Minimum interval between manual refreshes
MANUAL_REFRESH_COOLDOWN = timedelta(hours=1)
# Automatic refresh interval
AUTO_REFRESH_INTERVAL = 6 * 60 * 60  # 6 hours in seconds


class ScraperRunner:
    def __init__(self, engine):
        self.engine = engine
        self.last_manual_refresh: datetime | None = None
        self._stores = self._load_stores()

    def _load_stores(self) -> list[dict[str, str]]:
        """Load store configurations from environment variables."""
        stores = []
        for i in range(1, 10):
            name = os.getenv(f"STORE_{i}_NAME")
            url = os.getenv(f"STORE_{i}_URL")
            if name and url:
                stores.append({"name": name, "url": url})
        if not stores:
            # Defaults if no env vars set
            stores = [
                {"name": "Hemkop", "url": "https://www.hemkop.se/erbjudanden"},
                {"name": "Willys", "url": "https://www.willys.se/erbjudanden"},
                {"name": "Lidl", "url": "https://www.lidl.se/erbjudanden-och-rabatter"},
            ]
        return stores

    def _get_scraper_module(self, store_name: str):
        """Dynamically import the scraper module for a store."""
        # Normalize to ASCII (strip diacritics like ö→o), take first word only
        normalized = unicodedata.normalize("NFKD", store_name)
        ascii_name = normalized.encode("ascii", "ignore").decode("ascii")
        module_name = ascii_name.lower().split()[0].replace("-", "_") if ascii_name.split() else ""
        try:
            return importlib.import_module(f"scrapers.{module_name}")
        except ImportError:
            logger.warning("No scraper module found for store: %s", store_name)
            return None

    async def run_all_scrapers(self) -> dict[str, int]:
        """Run all store scrapers and save results to DB.

        Returns a dict of {store_name: deal_count}.
        """
        from main import Deal

        results: dict[str, int] = {}

        for store in self._stores:
            store_name = store["name"]
            store_url = store["url"]

            scraper = self._get_scraper_module(store_name)
            if not scraper:
                results[store_name] = 0
                continue

            try:
                logger.info("Scraping deals from %s (%s)...", store_name, store_url)
                deals_data = await scraper.scrape(store_url)
                logger.info("Found %d deals from %s", len(deals_data), store_name)

                # Replace all deals for this store in DB
                self._save_deals(store_name, deals_data, Deal)
                results[store_name] = len(deals_data)

            except Exception as e:
                logger.error("Error scraping %s: %s", store_name, e)
                results[store_name] = 0

        return results

    def _save_deals(self, store_name: str, deals_data: list[dict[str, Any]], deal_cls):
        """Replace all deals for a store in the database."""
        now = datetime.utcnow()

        with Session(self.engine) as session:
            # Delete existing deals for this store
            existing = session.exec(
                select(deal_cls).where(deal_cls.store_name == store_name)
            ).all()
            for deal in existing:
                session.delete(deal)

            # Insert new deals
            for data in deals_data:
                deal = deal_cls(
                    store_name=store_name,
                    product_name=data.get("product_name", "Unknown"),
                    description=data.get("description"),
                    original_price=data.get("original_price"),
                    deal_price=data.get("deal_price"),
                    discount_pct=data.get("discount_pct"),
                    category=data.get("category"),
                    valid_from=data.get("valid_from"),
                    valid_to=data.get("valid_to"),
                    image_url=data.get("image_url"),
                    scraped_at=now,
                )
                session.add(deal)

            session.commit()

    def get_last_refresh(self) -> datetime | None:
        """Return the most recent scraped_at timestamp from DB."""
        from main import Deal

        with Session(self.engine) as session:
            result = session.exec(
                select(Deal.scraped_at).order_by(Deal.scraped_at.desc()).limit(1)  # type: ignore[attr-defined]
            ).first()
            return result

    async def manual_refresh(self) -> dict[str, Any]:
        """Trigger a manual refresh, respecting rate limits."""
        now = datetime.utcnow()

        if self.last_manual_refresh:
            elapsed = now - self.last_manual_refresh
            if elapsed < MANUAL_REFRESH_COOLDOWN:
                remaining = MANUAL_REFRESH_COOLDOWN - elapsed
                return {
                    "status": "rate_limited",
                    "message": (
                        f"Manual refresh allowed once per hour. "
                        f"Try again in {int(remaining.total_seconds() // 60)} minutes."
                    ),
                }

        self.last_manual_refresh = now
        results = await self.run_all_scrapers()
        return {
            "status": "success",
            "message": "Deals refreshed successfully.",
            "stores": results,
        }


async def background_refresh_task(runner: ScraperRunner):
    """Background task: refresh on startup, then every 6 hours."""
    # Initial refresh on startup
    logger.info("Running initial deal scrape...")
    try:
        results = await runner.run_all_scrapers()
        logger.info("Initial scrape complete: %s", results)
    except Exception as e:
        logger.error("Initial scrape failed: %s", e)

    # Periodic refresh
    while True:
        await asyncio.sleep(AUTO_REFRESH_INTERVAL)
        logger.info("Running scheduled deal scrape...")
        try:
            results = await runner.run_all_scrapers()
            logger.info("Scheduled scrape complete: %s", results)
        except Exception as e:
            logger.error("Scheduled scrape failed: %s", e)
