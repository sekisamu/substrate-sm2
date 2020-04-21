

use substrate_subxt::{
	balances,
	Error,
	KusamaRuntime,
};

use sp_core::crypto::{Pair as PairT, Public as PublicT, AccountId32};
use crypto_sm2::sm2;



fn main() {
	async_std::task::block_on(async move {
		env_logger::init();

		let xt_result = transfer_balance().await;
		match xt_result {
			Ok(hash) => println!("Balance transfer extrinsic submitted: {}", hash),
			Err(_) => eprintln!("Balance transfer extrinisic failed"),
		}
	});
}


async fn transfer_balance() -> Result<sp_core::H256, Error> {
	// generate sm2 key-pair
	let signer = sm2::Pair::from_string("//Test", None).expect("static values are valid; qed");
	let dest = sm2::Pair::from_string("//Test1", None).expect("static values are valid; qed").public();

	// note use of `KusamaRuntime`
	substrate_subxt::ClientBuilder::<KusamaRuntime>::new()
		.build()
		.await?
		.xt(signer, None)
		.await?
		.submit(balances::transfer::<KusamaRuntime>(
			(dest.clone().into_b32()).into(),
			10_000,
		))
		.await
}
