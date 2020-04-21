

use substrate_subxt::{
	balances,
	Error,
	KusamaRuntime,
	system::System,
	ExtrinsicSuccess,
};

use sp_core::crypto::{Pair as PairT, Public as PublicT, AccountId32};
use crypto_sm2::sm2;

type AccountId = <KusamaRuntime as System>::AccountId;
type Balance = <KusamaRuntime as balances::Balances>::Balance;


fn main() {
	let result: Result<ExtrinsicSuccess<_>, Box<dyn std::error::Error + 'static>> =
		async_std::task::block_on(async move {
			env_logger::init();

			let signer = sm2::Pair::from_string("//Test", None).expect("static values are valid; qed");
			let dest = sm2::Pair::from_string("//Test1", None).expect("static values are valid; qed").public();


			let cli = substrate_subxt::ClientBuilder::<KusamaRuntime>::new()
				.build()
				.await?;
			let xt = cli.xt(signer, None).await?;
			let xt_result = xt
				.watch()
				.events_decoder(|decoder| {
					// for any primitive event with no type size registered
					decoder.register_type_size::<(u64, u64)>("IdentificationTuple")
				})
				.submit(balances::transfer::<KusamaRuntime>(dest.clone().into_b32().into(), 10_000))
				.await?;
			Ok(xt_result)
		});
	match result {
		Ok(extrinsic_success) => {
			match extrinsic_success
				.find_event::<(AccountId, AccountId, Balance)>("Balances", "Transfer")
				{
					Some(Ok((_from, _to, value))) => {
						println!("Balance transfer success: value: {:?}", value)
					}
					Some(Err(err)) => println!("Failed to decode code hash: {}", err),
					None => println!("Failed to find Balances::Transfer Event"),
				}
		}
		Err(err) => println!("Error: {:?}", err),
	}
}

