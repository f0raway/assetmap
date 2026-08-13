from assetmap.collectors import tyc_invest_crawler as crawler


def test_enterprise_discovery_uses_fixed_conservative_request_defaults():
    options = crawler.ClientOptions()
    crawl_options = crawler.CrawlOptions()

    assert options.delay == 0.2
    assert options.timeout == 6
    assert options.max_retries == 3
    assert crawl_options.skip_abnormal is True


def test_control_threshold_includes_equal_shareholding(monkeypatch):
    root = crawler.QueueItem(pid="root", name="根企业", depth=0, ref="root")
    result = crawler.create_result(root, crawler.CrawlOptions(threshold=47.0, max_depth=1))

    def fake_payload(_client, pid):
        if pid == "root":
            return (
                crawler.CompanyBasic(pid="root", name="根企业"),
                [crawler.Investment(pid="child", name="子企业", percent="47%", percent_value=47.0)],
                [], [], [], [],
            )
        return crawler.CompanyBasic(pid="child", name="子企业"), [], [], [], [], []

    monkeypatch.setattr(crawler, "fetch_company_payload", fake_payload)

    crawled = crawler.crawl_company_tree(object(), result, crawler.CrawlOptions(threshold=47.0, max_depth=1))

    assert {company["pid"] for company in crawled.companies} == {"root", "child"}
