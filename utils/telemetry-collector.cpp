#include "dht.hpp"
#include "td/utils/port/signals.h"
#include "td/utils/OptionParser.h"
#include "td/utils/filesystem.h"
#include "common/delay.h"
#include <fstream>
#include "overlay/overlays.h"

#include "auto/tl/ton_api_json.h"
#include "common/errorcode.h"

#include "tonlib/tonlib/TonlibClient.h"

#include "adnl/adnl.h"
#include "dht/dht.h"

#include <algorithm>
#include "td/utils/port/path.h"
#include "td/utils/JsonBuilder.h"
#include "auto/tl/ton_api_json.h"
#include "auto/tl/tonlib_api.hpp"
#include "tl/tl_json.h"

#include "git.h"

using namespace ton;

td::IPAddress ip_addr;
std::string global_config;
std::string output_filename;

class TelemetryCollector : public td::actor::Actor {
 public:
  TelemetryCollector() = default;

  td::Result<td::BufferSlice> load_global_config() {
    TRY_RESULT_PREFIX(conf_data, td::read_file(global_config), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");
    ton_api::config_global conf;
    TRY_STATUS_PREFIX(ton_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");
    if (!conf.dht_) {
      return td::Status::Error(ErrorCode::error, "does not contain [dht] section");
    }
    TRY_RESULT_PREFIX(dht, dht::Dht::create_global_config(std::move(conf.dht_)), "bad [dht] section: ");
    dht_config_ = std::move(dht);
    zerostate_hash_ = conf.validator_->zero_state_->file_hash_;
    return conf_data;
  }

  void run() {
    if (output_filename.empty()) {
      output_ = &std::cout;
    } else {
      out_file_.open(output_filename, std::ios_base::app);
      LOG_CHECK(out_file_.is_open()) << "Cannot open " << output_filename;
      output_ = &out_file_;
    }

    keyring_ = keyring::Keyring::create("");
    auto r_conf_data = load_global_config();
    r_conf_data.ensure();

    adnl_network_manager_ = adnl::AdnlNetworkManager::create(0);
    adnl_ = adnl::Adnl::create("", keyring_.get());
    td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, adnl_network_manager_.get());
    adnl::AdnlCategoryMask cat_mask;
    cat_mask[0] = true;
    td::actor::send_closure(adnl_network_manager_, &adnl::AdnlNetworkManager::add_self_addr, ip_addr,
                            std::move(cat_mask), 0);
    addr_list_.set_version(static_cast<td::int32>(td::Clocks::system()));
    addr_list_.set_reinit_date(adnl::Adnl::adnl_start_time());
    addr_list_.add_udp_address(ip_addr);
    {
      auto pk = PrivateKey{privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(pk), true, [](td::Unit) {});
      dht_id_ = adnl::AdnlNodeIdShort{pub.compute_short_id()};
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{pub}, addr_list_,
                              static_cast<td::uint8>(0));
    }
    {
      auto pk = PrivateKey{privkeys::Ed25519::random()};
      auto pub = pk.compute_public_key();
      td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(pk), true, [](td::Unit) {});
      local_id_ = adnl::AdnlNodeIdShort{pub.compute_short_id()};
      td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{pub}, addr_list_,
                              static_cast<td::uint8>(0));
    }
    auto D = dht::Dht::create_client(dht_id_, "", dht_config_, keyring_.get(), adnl_.get());
    D.ensure();
    dht_ = D.move_as_ok();
    td::actor::send_closure(adnl_, &adnl::Adnl::register_dht_node, dht_.get());

    auto tonlib_options = create_tl_object<ton::tonlib_api::options>(
        create_tl_object<ton::tonlib_api::config>(r_conf_data.ok().as_slice().str(), "", false, false),
        create_tl_object<ton::tonlib_api::keyStoreTypeInMemory>());
    class TonlibCb : public tonlib::TonlibCallback {
     public:
      void on_result(std::uint64_t id, ton::tonlib_api::object_ptr<ton::tonlib_api::Object> result) override {
      }
      void on_error(std::uint64_t id, ton::tonlib_api::object_ptr<ton::tonlib_api::error> error) override {
      }
    };
    tonlib_client_ = td::actor::create_actor<tonlib::TonlibClient>("tonlibclient", td::make_unique<TonlibCb>());
    ton::tonlib_api::init init{std::move(tonlib_options)};
    td::actor::send_closure(
        tonlib_client_,
        &tonlib::TonlibClient::make_request<ton::tonlib_api::init,
                                            td::Promise<tl_object_ptr<ton::tonlib_api::options_info>>>,
        std::move(init), [SelfId = actor_id(this)](td::Result<tl_object_ptr<ton::tonlib_api::options_info>> R) {
          R.ensure();
          td::actor::send_closure(SelfId, &TelemetryCollector::tonlib_inited);
        });
  }

  void tonlib_inited() {
    LOG(WARNING) << "Syncing tonlib";
    td::actor::send_closure(
        tonlib_client_,
        &tonlib::TonlibClient::make_request<ton::tonlib_api::sync,
                                            td::Promise<tl_object_ptr<ton::tonlib_api::ton_blockIdExt>>>,
        ton::tonlib_api::sync{},
        [SelfId = actor_id(this)](td::Result<tl_object_ptr<ton::tonlib_api::ton_blockIdExt>> R) {
          if (R.is_error()) {
            LOG(ERROR) << "Tonlib sync error: " << R.move_as_error();
            delay_action([=]() { td::actor::send_closure(SelfId, &TelemetryCollector::tonlib_inited); },
                         td::Timestamp::in(1.0));
          } else {
            td::actor::send_closure(SelfId, &TelemetryCollector::tonlib_synced);
          }
        });
  }

  void tonlib_synced() {
    LOG(WARNING) << "Sync complete";
    get_validator_sets();
  }

  void get_validator_sets() {
    td::actor::send_closure(
        tonlib_client_,
        &tonlib::TonlibClient::make_request<ton::tonlib_api::getConfigAll,
                                            td::Promise<tl_object_ptr<ton::tonlib_api::configInfo>>>,
        ton::tonlib_api::getConfigAll{0},
        [SelfId = actor_id(this)](td::Result<tl_object_ptr<ton::tonlib_api::configInfo>> R) {
          if (R.is_error()) {
            LOG(ERROR) << "Tonlib getConfigAll: " << R.move_as_error();
            delay_action([=]() { td::actor::send_closure(SelfId, &TelemetryCollector::get_validator_sets); },
                         td::Timestamp::in(1.0));
          } else {
            td::actor::send_closure(SelfId, &TelemetryCollector::got_config, R.move_as_ok());
          }
        });
  }

  void got_config(tl_object_ptr<ton::tonlib_api::configInfo> data) {
    alarm_timestamp() = td::Timestamp::in(60.0);
    td::Ref<vm::Cell> root = vm::std_boc_deserialize(data->config_->bytes_).move_as_ok();
    if (td::Bits256{root->get_hash().bits()} == last_config_hash_) {
      return;
    }
    last_config_hash_ = root->get_hash().bits();
    authorized_keys_.clear();
    vm::Dictionary dict{root, 32};
    for (td::int32 idx : {32, 34, 36}) {
      td::Ref<vm::Cell> param = dict.lookup_ref(td::BitArray<32>(idx));
      if (param.is_null()) {
        continue;
      }
      auto r_validator_set = block::Config::unpack_validator_set(param);
      r_validator_set.ensure();
      for (const auto& desc : r_validator_set.ok()->export_validator_set()) {
        PublicKeyHash key_hash =
            desc.addr.is_zero() ? PublicKey{pubkeys::Ed25519{desc.key}}.compute_short_id() : PublicKeyHash{desc.addr};
        authorized_keys_[key_hash] = MAX_BROADCAST_SIZE;
      }
    }
    LOG(WARNING) << "Got " << authorized_keys_.size() << " validator keys from config (params 32, 34, 36)";
    if (overlay_created_) {
      overlay::OverlayPrivacyRules rules{0, 0, authorized_keys_};
      td::actor::send_closure(overlays_, &overlay::Overlays::set_privacy_rules, local_id_, overlay_id_,
                              std::move(rules));
    } else {
      create_overlay();
    }
  }

  void alarm() override {
    get_validator_sets();
  }

  void create_overlay() {
    overlays_ = overlay::Overlays::create("", keyring_.get(), adnl_.get(), dht_.get());

    class Callback : public overlay::Overlays::Callback {
     public:
      explicit Callback(td::actor::ActorId<TelemetryCollector> id) : id_(id) {
      }
      void receive_message(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id,
                           td::BufferSlice data) override {
      }
      void receive_query(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id, td::BufferSlice data,
                         td::Promise<td::BufferSlice> promise) override {
      }
      void receive_broadcast(PublicKeyHash src, overlay::OverlayIdShort overlay_id, td::BufferSlice data) override {
        td::actor::send_closure(id_, &TelemetryCollector::receive_broadcast, src, std::move(data));
      }
      void check_broadcast(PublicKeyHash src, overlay::OverlayIdShort overlay_id, td::BufferSlice data,
                           td::Promise<td::Unit> promise) override {
      }

     private:
      td::actor::ActorId<TelemetryCollector> id_;
    };

    auto X = create_hash_tl_object<ton_api::validator_telemetryOverlayId>(zerostate_hash_);
    td::BufferSlice b{32};
    b.as_slice().copy_from(as_slice(X));
    overlay::OverlayIdFull overlay_id_full{std::move(b)};
    overlay::OverlayPrivacyRules rules{0, 0, authorized_keys_};
    overlay::OverlayOptions opts;
    opts.frequent_dht_lookup_ = true;
    overlay_id_ = overlay_id_full.compute_short_id();
    LOG(WARNING) << "Overlay id : " << overlay_id_;
    overlay_created_ = true;
    td::actor::send_closure(overlays_, &overlay::Overlays::create_public_overlay_ex, local_id_,
                            std::move(overlay_id_full), std::make_unique<Callback>(actor_id(this)), std::move(rules),
                            R"({ "type": "telemetry" })", opts);
  }

  void receive_broadcast(PublicKeyHash src, td::BufferSlice data) {
    auto R = fetch_tl_prefix<ton_api::validator_telemetry>(data, true);
    if (R.is_error()) {
      LOG(WARNING) << "Invalid broadcast from " << src << ": " << R.move_as_error();
      return;
    }
    auto telemetry = R.move_as_ok();
    if (telemetry->adnl_id_ != src.bits256_value()) {
      LOG(WARNING) << "Invalid broadcast from " << src << ": adnl_id mismatch";
      return;
    }
    LOG(INFO) << "Got broadcast from " << src;
    auto s = td::json_encode<std::string>(td::ToJson(*telemetry), false);
    std::erase_if(s, [](char c) { return c == '\n' || c == '\r'; });
    (*output_) << s << "\n";
    output_->flush();
    if (output_->fail()) {
      LOG(ERROR) << "Output error";
    }
  }

 private:
  adnl::AdnlNodeIdShort dht_id_, local_id_;
  adnl::AdnlAddressList addr_list_;

  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::AdnlNetworkManager> adnl_network_manager_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<dht::Dht> dht_;
  td::actor::ActorOwn<overlay::Overlays> overlays_;

  std::shared_ptr<dht::DhtGlobalConfig> dht_config_;
  td::Bits256 zerostate_hash_;

  td::actor::ActorOwn<tonlib::TonlibClient> tonlib_client_;

  bool overlay_created_ = false;
  overlay::OverlayIdShort overlay_id_;
  td::Bits256 last_config_hash_ = td::Bits256::zero();
  std::map<PublicKeyHash, td::uint32> authorized_keys_;

  std::ofstream out_file_;
  std::ostream* output_;

  static constexpr td::uint32 MAX_BROADCAST_SIZE = 8192;
};

int main(int argc, char* argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);

  td::set_default_failure_signal_handler().ensure();

  td::actor::ActorOwn<TelemetryCollector> x;
  td::unique_ptr<td::LogInterface> logger_;
  SCOPE_EXIT {
    td::log_interface = td::default_log_interface;
  };

  td::OptionParser p;
  p.set_description("collect validator telemetry from the overlay, print as json to stdout\n");
  p.add_option('v', "verbosity", "set verbosity level", [&](td::Slice arg) {
    int v = VERBOSITY_NAME(FATAL) + (td::to_integer<int>(arg));
    SET_VERBOSITY_LEVEL(v);
  });
  p.add_option('h', "help", "prints a help message", [&]() {
    char b[10240];
    td::StringBuilder sb(td::MutableSlice{b, 10000});
    sb << p;
    std::cout << sb.as_cslice().c_str();
    std::exit(2);
  });
  p.add_option('V', "version", "shows build information", [&]() {
    std::cout << "telemetry-collector build information: [ Commit: " << GitMetadata::CommitSHA1()
              << ", Date: " << GitMetadata::CommitDate() << "]\n";
    std::exit(0);
  });
  p.add_option('C', "global-config", "global TON configuration file",
               [&](td::Slice arg) { global_config = arg.str(); });
  p.add_checked_option('a', "addr", "ip:port", [&](td::Slice arg) {
    TRY_STATUS(ip_addr.init_host_port(arg.str()));
    return td::Status::OK();
  });
  p.add_option('o', "output", "output file (default: stdout)",
               [&](td::Slice arg) { output_filename = arg.str(); });

  td::actor::Scheduler scheduler({3});

  scheduler.run_in_context([&] { x = td::actor::create_actor<TelemetryCollector>("collector"); });
  scheduler.run_in_context([&] { p.run(argc, argv).ensure(); });
  scheduler.run_in_context([&] { td::actor::send_closure(x, &TelemetryCollector::run); });
  while (scheduler.run(1)) {
  }

  return 0;
}
