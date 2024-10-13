/*
    This file is part of TON Blockchain source code.

    TON Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TON Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TON Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.
*/
#include "validator-telemetry.hpp"
#include "git.h"
#include "td/utils/Random.h"
#include "td/utils/port/uname.h"

#include <delay.h>

namespace ton::validator {

void ValidatorTelemetry::start_up() {
  node_version_ = PSTRING() << "validator-engine, Commit: " << GitMetadata::CommitSHA1()
                            << ", Date: " << GitMetadata::CommitDate();

  os_version_ = td::get_operating_system_version().str();

  auto r_total_mem_stat = td::get_total_mem_stat();
  if (r_total_mem_stat.is_error()) {
    LOG(WARNING) << "Cannot get RAM size: " << r_total_mem_stat.move_as_error();
  } else {
    ram_size_ = r_total_mem_stat.ok().total_ram;
  }

  auto r_cpu_cores = td::get_cpu_cores();
  if (r_cpu_cores.is_error()) {
    LOG(WARNING) << "Cannot get CPU info: " << r_cpu_cores.move_as_error();
  } else {
    cpu_cores_ = r_cpu_cores.move_as_ok();
  }

  try_init();
}

void ValidatorTelemetry::try_init() {
  // Sometimes validator adnl id is added to validator engine later (or not at all)
  td::actor::send_closure(
      adnl_, &adnl::Adnl::check_id_exists, local_id_, [SelfId = actor_id(this)](td::Result<bool> R) {
        if (R.is_ok() && R.ok()) {
          td::actor::send_closure(SelfId, &ValidatorTelemetry::init);
        } else {
          delay_action([SelfId]() { td::actor::send_closure(SelfId, &ValidatorTelemetry::try_init); },
                       td::Timestamp::in(60.0));
        }
      });
}

void ValidatorTelemetry::init() {
  class Callback : public overlay::Overlays::Callback {
   public:
    void receive_message(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id, td::BufferSlice data) override {
    }
    void receive_query(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id, td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
    }
    void receive_broadcast(PublicKeyHash src, overlay::OverlayIdShort overlay_id, td::BufferSlice data) override {
    }
    void check_broadcast(PublicKeyHash src, overlay::OverlayIdShort overlay_id, td::BufferSlice data,
                         td::Promise<td::Unit> promise) override {
    }
  };

  inited_ = true;
  auto X = create_hash_tl_object<ton_api::validator_telemetryOverlayId>(zero_state_file_hash_);
  td::BufferSlice b{32};
  b.as_slice().copy_from(as_slice(X));
  overlay::OverlayIdFull overlay_id_full{std::move(b)};
  overlay_id_ = overlay_id_full.compute_short_id();
  overlay::OverlayPrivacyRules rules{0, 0, authorized_keys_};
  td::actor::send_closure(overlays_, &overlay::Overlays::create_public_overlay, local_id_, std::move(overlay_id_full),
                          std::make_unique<Callback>(), std::move(rules), R"({ "type": "telemetry" })");
  LOG(DEBUG) << "Creating validator telemetry overlay for adnl id " << local_id_ << ", overlay_id=" << overlay_id_;

  alarm_timestamp().relax(send_telemetry_at_ = td::Timestamp::in(td::Random::fast(30.0, 60.0)));
}

void ValidatorTelemetry::update_validators(td::Ref<MasterchainState> state) {
  authorized_keys_.clear();
  for (int i = -1; i <= 1; ++i) {
    auto set = state->get_total_validator_set(i);
    if (set.is_null()) {
      continue;
    }
    for (const ValidatorDescr& val : set->export_vector()) {
      PublicKeyHash adnl_id;
      if (val.addr.is_zero()) {
        adnl_id = ValidatorFullId{val.key}.compute_short_id();
      } else {
        adnl_id = PublicKeyHash{val.addr};
      }
      authorized_keys_[adnl_id] = MAX_SIZE;
    }
  }
  if (inited_) {
    overlay::OverlayPrivacyRules rules{0, 0, authorized_keys_};
    td::actor::send_closure(overlays_, &overlay::Overlays::set_privacy_rules, local_id_, overlay_id_, std::move(rules));
  }
}

void ValidatorTelemetry::alarm() {
  if (send_telemetry_at_.is_in_past()) {
    send_telemetry_at_ = td::Timestamp::never();
    send_telemetry();
  }
  alarm_timestamp().relax(send_telemetry_at_);
}

void ValidatorTelemetry::send_telemetry() {
  send_telemetry_at_ = td::Timestamp::in(PERIOD);
  if (!authorized_keys_.count(local_id_.pubkey_hash())) {
    LOG(DEBUG) << "Skipping sending validator telemetry for adnl id " << local_id_ << ": not authorized";
    return;
  }

  auto telemetry = create_tl_object<ton_api::validator_telemetry>();
  telemetry->flags_ = 0;
  telemetry->timestamp_ = td::Clocks::system();
  telemetry->adnl_id_ = local_id_.bits256_value();
  telemetry->node_version_ = node_version_;
  telemetry->os_version_ = os_version_;
  telemetry->ram_size_ = ram_size_;
  telemetry->cpu_cores_ = cpu_cores_;
  telemetry->node_threads_ = (td::int32)td::actor::SchedulerContext::get()
                                 ->scheduler_group()
                                 ->schedulers.at(td::actor::SchedulerContext::get()->get_scheduler_id().value())
                                 .cpu_threads_count;

  td::BufferSlice data = serialize_tl_object(telemetry, true);
  LOG(DEBUG) << "Sending validator telemetry for adnl id " << local_id_ << ", size=" << data.size();
  if (data.size() <= overlay::Overlays::max_simple_broadcast_size()) {
    td::actor::send_closure(overlays_, &overlay::Overlays::send_broadcast, local_id_, overlay_id_, std::move(data));
  } else {
    td::actor::send_closure(overlays_, &overlay::Overlays::send_broadcast_fec, local_id_, overlay_id_, std::move(data));
  }
}

}  // namespace ton::validator
